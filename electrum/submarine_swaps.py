import asyncio
import json
import os
from typing import TYPE_CHECKING, Optional, Dict, Union

import attr

from .crypto import sha256, hash_160
from .ecc import ECPrivkey
from .bitcoin import address_to_script, script_to_p2wsh, redeem_script_to_address, opcodes, p2wsh_nested_script, push_script, is_segwit_address
from .transaction import TxOutpoint, PartialTxInput, PartialTxOutput, PartialTransaction, construct_witness
from .transaction import script_GetOp, match_script_against_template, OPPushDataGeneric, OPPushDataPubkey
from .util import log_exceptions
from .lnutil import REDEEM_AFTER_DOUBLE_SPENT_DELAY, ln_dummy_address, LN_MAX_HTLC_VALUE_MSAT
from .bitcoin import dust_threshold
from .logging import Logger
from .lnutil import hex_to_bytes
from .json_db import StoredObject
from . import constants


if TYPE_CHECKING:
    from .network import Network
    from .wallet import Abstract_Wallet


API_URL_MAINNET = 'https://swaps.electrum.org/api'
API_URL_TESTNET = 'https://swaps.electrum.org/testnet'
API_URL_REGTEST = 'https://localhost/api'



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
    onchain_amount = attr.ib(type=int)  # in sats
    lightning_amount = attr.ib(type=int)  # in sats
    redeem_script = attr.ib(type=bytes, converter=hex_to_bytes)
    preimage = attr.ib(type=bytes, converter=hex_to_bytes)
    prepay_hash = attr.ib(type=Optional[bytes], converter=hex_to_bytes)
    privkey = attr.ib(type=bytes, converter=hex_to_bytes)
    lockup_address = attr.ib(type=str)
    funding_txid = attr.ib(type=Optional[str])
    spending_txid = attr.ib(type=Optional[str])
    is_redeemed = attr.ib(type=bool)


def create_claim_tx(
        *,
        txin: PartialTxInput,
        witness_script: bytes,
        preimage: Union[bytes, int],  # 0 if timing out forward-swap
        privkey: bytes,
        address: str,
        amount_sat: int,
        locktime: int,
) -> PartialTransaction:
    """Create tx to either claim successful reverse-swap,
    or to get refunded for timed-out forward-swap.
    """
    if is_segwit_address(txin.address):
        txin.script_type = 'p2wsh'
        txin.script_sig = b''
    else:
        txin.script_type = 'p2wsh-p2sh'
        txin.redeem_script = bytes.fromhex(p2wsh_nested_script(witness_script.hex()))
        txin.script_sig = bytes.fromhex(push_script(txin.redeem_script.hex()))
    txin.witness_script = witness_script
    txout = PartialTxOutput.from_address_and_value(address, amount_sat)
    tx = PartialTransaction.from_io([txin], [txout], version=2, locktime=locktime)
    #tx.set_rbf(True)
    sig = bytes.fromhex(tx.sign_txin(0, privkey))
    witness = [sig, preimage, witness_script]
    txin.witness = bytes.fromhex(construct_witness(witness))
    return tx


class SwapManager(Logger):

    def __init__(self, wallet: 'Abstract_Wallet', network: 'Network'):
        Logger.__init__(self)
        self.normal_fee = 0
        self.lockup_fee = 0
        self.percentage = 0
        self.min_amount = 0
        self._max_amount = 0
        self.network = network
        self.wallet = wallet
        self.lnworker = wallet.lnworker
        self.lnwatcher = self.wallet.lnworker.lnwatcher
        self.swaps = self.wallet.db.get_dict('submarine_swaps')  # type: Dict[str, SwapData]
        self.prepayments = {}  # type: Dict[bytes, bytes] # fee_preimage -> preimage
        for k, swap in self.swaps.items():
            if swap.is_reverse and swap.prepay_hash is not None:
                self.prepayments[swap.prepay_hash] = bytes.fromhex(k)
            if swap.is_redeemed:
                continue
            self.add_lnwatcher_callback(swap)
        # api url
        if constants.net == constants.BitcoinMainnet:
            self.api_url = API_URL_MAINNET
        elif constants.net == constants.BitcoinTestnet:
            self.api_url = API_URL_TESTNET
        else:
            self.api_url = API_URL_REGTEST

    @log_exceptions
    async def _claim_swap(self, swap: SwapData) -> None:
        if not self.lnwatcher.is_up_to_date():
            return
        current_height = self.network.get_local_height()
        delta = current_height - swap.locktime
        if not swap.is_reverse and delta < 0:
            # too early for refund
            return
        txos = self.lnwatcher.get_addr_outputs(swap.lockup_address)
        for txin in txos.values():
            if swap.is_reverse and txin.value_sats() < swap.onchain_amount:
                self.logger.info('amount too low, we should not reveal the preimage')
                continue
            spent_height = txin.spent_height
            if spent_height is not None:
                if spent_height > 0 and current_height - spent_height > REDEEM_AFTER_DOUBLE_SPENT_DELAY:
                    self.logger.info(f'stop watching swap {swap.lockup_address}')
                    self.lnwatcher.remove_callback(swap.lockup_address)
                    swap.is_redeemed = True
                continue
            amount_sat = txin.value_sats() - self.get_claim_fee()
            if amount_sat < dust_threshold():
                self.logger.info('utxo value below dust threshold')
                continue
            address = self.wallet.get_receiving_address()
            if swap.is_reverse:  # successful reverse swap
                preimage = swap.preimage
                locktime = 0
            else:  # timing out forward swap
                preimage = 0
                locktime = swap.locktime
            tx = create_claim_tx(
                txin=txin,
                witness_script=swap.redeem_script,
                preimage=preimage,
                privkey=swap.privkey,
                address=address,
                amount_sat=amount_sat,
                locktime=locktime,
            )
            await self.network.broadcast_transaction(tx)
            # save txid
            if swap.is_reverse:
                swap.spending_txid = tx.txid()
            else:
                self.wallet.set_label(tx.txid(), 'Swap refund')

    def get_claim_fee(self):
        return self.lnwatcher.config.estimate_fee(136, allow_fallback_to_static_rates=True)

    def get_swap(self, payment_hash: bytes) -> Optional[SwapData]:
        # for history
        swap = self.swaps.get(payment_hash.hex())
        if swap:
            return swap
        payment_hash = self.prepayments.get(payment_hash)
        if payment_hash:
            return self.swaps.get(payment_hash.hex())

    def add_lnwatcher_callback(self, swap: SwapData) -> None:
        callback = lambda: self._claim_swap(swap)
        self.lnwatcher.add_callback(swap.lockup_address, callback)

    async def normal_swap(self, lightning_amount: int, expected_onchain_amount: int,
                          password, *, tx: PartialTransaction = None) -> str:
        """send on-chain BTC, receive on Lightning"""
        privkey = os.urandom(32)
        pubkey = ECPrivkey(privkey).get_public_key_bytes(compressed=True)
        lnaddr, invoice = await self.lnworker.create_invoice(lightning_amount, 'swap', expiry=3600*24)
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
            self.api_url + '/createswap',
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
        if not match_script_against_template(redeem_script, WITNESS_TEMPLATE_SWAP):
            raise Exception("fswap check failed: scriptcode does not match template")
        if script_to_p2wsh(redeem_script.hex()) != lockup_address:
            raise Exception("fswap check failed: inconsistent scriptcode and address")
        if hash_160(preimage) != parsed_script[1][1]:
            raise Exception("fswap check failed: our preimage not in script")
        if pubkey != parsed_script[9][1]:
            raise Exception("fswap check failed: our pubkey not in script")
        if locktime != int.from_bytes(parsed_script[6][1], byteorder='little'):
            raise Exception("fswap check failed: inconsistent locktime and script")
        # check that onchain_amount is not more than what we estimated
        if onchain_amount > expected_onchain_amount:
            raise Exception(f"fswap check failed: onchain_amount is more than what we estimated: "
                            f"{onchain_amount} > {expected_onchain_amount}")
        # verify that they are not locking up funds for more than a day
        if locktime - self.network.get_local_height() >= 144:
            raise Exception("fswap check failed: locktime too far in future")
        # create funding tx
        funding_output = PartialTxOutput.from_address_and_value(lockup_address, expected_onchain_amount)
        if tx is None:
            tx = self.wallet.create_transaction(outputs=[funding_output], rbf=False, password=password)
        else:
            dummy_output = PartialTxOutput.from_address_and_value(ln_dummy_address(), expected_onchain_amount)
            tx.outputs().remove(dummy_output)
            tx.add_outputs([funding_output])
            tx.set_rbf(False)
            self.wallet.sign_transaction(tx, password)
        # save swap data in wallet in case we need a refund
        swap = SwapData(
            redeem_script = redeem_script,
            locktime = locktime,
            privkey = privkey,
            preimage = preimage,
            prepay_hash = None,
            lockup_address = lockup_address,
            onchain_amount = expected_onchain_amount,
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

    async def reverse_swap(self, amount_sat: int, expected_amount: int) -> bool:
        """send on Lightning, receive on-chain"""
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
            self.api_url + '/createswap',
            json=request_data,
            timeout=30)
        data = json.loads(response)
        invoice = data['invoice']
        fee_invoice = data.get('minerFeeInvoice')
        lockup_address = data['lockupAddress']
        redeem_script = data['redeemScript']
        locktime = data['timeoutBlockHeight']
        onchain_amount = data["onchainAmount"]
        response_id = data['id']
        # verify redeem_script is built with our pubkey and preimage
        redeem_script = bytes.fromhex(redeem_script)
        parsed_script = [x for x in script_GetOp(redeem_script)]
        if not match_script_against_template(redeem_script, WITNESS_TEMPLATE_REVERSE_SWAP):
            raise Exception("rswap check failed: scriptcode does not match template")
        if script_to_p2wsh(redeem_script.hex()) != lockup_address:
            raise Exception("rswap check failed: inconsistent scriptcode and address")
        if hash_160(preimage) != parsed_script[5][1]:
            raise Exception("rswap check failed: our preimage not in script")
        if pubkey != parsed_script[7][1]:
            raise Exception("rswap check failed: our pubkey not in script")
        if locktime != int.from_bytes(parsed_script[10][1], byteorder='little'):
            raise Exception("rswap check failed: inconsistent locktime and script")
        # check that the onchain amount is what we expected
        if onchain_amount < expected_amount:
            raise Exception(f"rswap check failed: onchain_amount is less than what we expected: "
                            f"{onchain_amount} < {expected_amount}")
        # verify that we will have enough time to get our tx confirmed
        if locktime - self.network.get_local_height() <= 60:
            raise Exception("rswap check failed: locktime too close")
        # verify invoice preimage_hash
        lnaddr = self.lnworker._check_invoice(invoice)
        invoice_amount = lnaddr.get_amount_sat()
        if lnaddr.paymenthash != preimage_hash:
            raise Exception("rswap check failed: inconsistent RHASH and invoice")
        # check that the lightning amount is what we requested
        if fee_invoice:
            fee_lnaddr = self.lnworker._check_invoice(fee_invoice)
            invoice_amount += fee_lnaddr.get_amount_sat()
            prepay_hash = fee_lnaddr.paymenthash
        else:
            prepay_hash = None
        if int(invoice_amount) != amount_sat:
            raise Exception(f"rswap check failed: invoice_amount ({invoice_amount}) "
                            f"not what we requested ({amount_sat})")
        # save swap data to wallet file
        swap = SwapData(
            redeem_script = redeem_script,
            locktime = locktime,
            privkey = privkey,
            preimage = preimage,
            prepay_hash = prepay_hash,
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
        if fee_invoice:
            self.prepayments[prepay_hash] = preimage_hash
            asyncio.ensure_future(self.lnworker._pay(fee_invoice, attempts=10))
        # initiate payment.
        success, log = await self.lnworker._pay(invoice, attempts=10)
        return success

    async def get_pairs(self) -> None:
        response = await self.network._send_http_on_proxy(
            'get',
            self.api_url + '/getpairs',
            timeout=30)
        pairs = json.loads(response)
        fees = pairs['pairs']['BTC/BTC']['fees']
        self.percentage = fees['percentage']
        self.normal_fee = fees['minerFees']['baseAsset']['normal']
        self.lockup_fee = fees['minerFees']['baseAsset']['reverse']['lockup']
        limits = pairs['pairs']['BTC/BTC']['limits']
        self.min_amount = limits['minimal']
        self._max_amount = limits['maximal']

    def get_max_amount(self):
        return min(self._max_amount, LN_MAX_HTLC_VALUE_MSAT // 1000)

    def check_invoice_amount(self, x):
        return x >= self.min_amount and x <= self._max_amount

    def get_recv_amount(self, send_amount: Optional[int], is_reverse: bool) -> Optional[int]:
        if send_amount is None:
            return
        x = send_amount
        if is_reverse:
            if not self.check_invoice_amount(x):
                return
            x = int(x * (100 - self.percentage) / 100)
            x -= self.lockup_fee
            x -= self.get_claim_fee()
        else:
            x -= self.normal_fee
            x = int(x * (100 - self.percentage) / 100)
            if not self.check_invoice_amount(x):
                return
        return x

    def get_send_amount(self, recv_amount: Optional[int], is_reverse: bool) -> Optional[int]:
        if not recv_amount:
            return
        x = recv_amount
        if is_reverse:
            x += self.lockup_fee
            x += self.get_claim_fee()
            x = int(x * 100 / (100 - self.percentage)) + 1
            if not self.check_invoice_amount(x):
                return
        else:
            if not self.check_invoice_amount(x):
                return
            x = int(x * 100 / (100 - self.percentage)) + 1
            x += self.normal_fee
        return x

