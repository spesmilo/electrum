import asyncio
import json
import logging
import threading
import time
from decimal import Decimal
from types import SimpleNamespace
from unittest import mock

from electrum_ecc import ECPrivkey

from electrum import bitcoin
from electrum.address_synchronizer import TX_HEIGHT_LOCAL
from electrum.crypto import sha256
from electrum.invoices import Invoice, PR_INFLIGHT, PR_PAID, PR_UNPAID
from electrum.plugins.swapserver.server import HttpSwapServer
from electrum.submarine_swaps import (
    COOPERATIVE_SWAP_TX_SIZE,
    MUSIG_SESSION_MAX_ENTRIES,
    MUSIG_SESSION_TTL_SEC,
    TAPROOT_COOPERATIVE_CAPABILITY,
    TAPROOT_SWAP_PROTOCOL,
    HttpTransport,
    NostrTransport,
    SwapData,
    SwapFees,
    SwapManager,
    SwapOffer,
    SwapServerError,
    _construct_swap_scriptcode,
)
from electrum.taproot_swaps import MuSig2Session, SwapDirection, SwapLeaf, TaprootSwapContract
from electrum.transaction import (
    PartialTransaction,
    PartialTxInput,
    PartialTxOutput,
    Transaction,
    TxOutpoint,
    TxOutput,
)
from electrum.util import MyEncoder

from . import ElectrumTestCase


PROVIDER_SECKEY = bytes.fromhex(
    "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef"
)
USER_SECKEY = bytes.fromhex(
    "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9"
)
PROVIDER_PUBKEY = ECPrivkey(PROVIDER_SECKEY).get_public_key_bytes(compressed=True)
USER_PUBKEY = ECPrivkey(USER_SECKEY).get_public_key_bytes(compressed=True)
PREIMAGE = b"\xaa" * 32
PAYMENT_HASH = sha256(PREIMAGE)
LOCKTIME = 800_000
LOCAL_HEIGHT = LOCKTIME - 70
ONCHAIN_AMOUNT = 1_000_000
LIGHTNING_AMOUNT = 1_001_000
FEE = 500


def destination_address() -> str:
    pubkey = ECPrivkey(b"\x42" * 32).get_public_key_bytes(compressed=True).hex()
    return bitcoin.pubkey_to_address("p2wpkh", pubkey)


def alternate_destination_address() -> str:
    pubkey = ECPrivkey(b"\x43" * 32).get_public_key_bytes(compressed=True).hex()
    return bitcoin.pubkey_to_address("p2wpkh", pubkey)


def contract(direction: SwapDirection, *, payment_hash=PAYMENT_HASH) -> TaprootSwapContract:
    return TaprootSwapContract(
        direction=direction,
        payment_hash=payment_hash,
        locktime=LOCKTIME,
        provider_pubkey=PROVIDER_PUBKEY,
        user_pubkey=USER_PUBKEY,
    )


def make_swap(
    *, direction: SwapDirection, is_provider: bool, is_cooperative: bool = True,
) -> SwapData:
    swap_contract = contract(direction)
    is_reverse = (direction is SwapDirection.REVERSE) ^ is_provider
    swap = SwapData(
        is_reverse=is_reverse,
        locktime=LOCKTIME,
        onchain_amount=ONCHAIN_AMOUNT,
        lightning_amount=LIGHTNING_AMOUNT,
        redeem_script=swap_contract.output_script,
        preimage=PREIMAGE if is_reverse else None,
        prepay_hash=None,
        privkey=PROVIDER_SECKEY if is_provider else USER_SECKEY,
        lockup_address=swap_contract.address(),
        claim_to_output=None,
        funding_txid=None,
        spending_txid=None,
        is_redeemed=False,
        protocol=TAPROOT_SWAP_PROTOCOL,
        their_pubkey=USER_PUBKEY if is_provider else PROVIDER_PUBKEY,
        is_provider=is_provider,
        is_cooperative=is_cooperative,
    )
    swap._payment_hash = PAYMENT_HASH
    return swap


def make_funding(swap: SwapData, *, amount=ONCHAIN_AMOUNT, scriptpubkey=None):
    source = PartialTxInput(prevout=TxOutpoint(txid=b"\x33" * 32, out_idx=0))
    source.script_sig = b""
    source.nsequence = 0xffffffff
    source.witness = bitcoin.construct_witness([b"funding"])
    funding_txout = TxOutput(
        scriptpubkey=swap.redeem_script if scriptpubkey is None else scriptpubkey,
        value=amount,
    )
    funding = PartialTransaction.from_io(
        [source], [PartialTxOutput.from_txout(funding_txout)], version=2, BIP69_sort=False,
    )
    funding_tx = Transaction(funding.serialize_to_network())
    swap.funding_txid = funding_tx.txid()
    prevout = TxOutpoint(txid=bytes.fromhex(swap.funding_txid), out_idx=0)
    swap._funding_prevout = prevout
    watched = PartialTxInput(prevout=prevout)
    watched._trusted_address = swap.lockup_address
    watched._trusted_value_sats = amount
    watched.spent_height = None
    watched.spent_txid = None
    return funding_tx, funding_txout, watched


def logger():
    return logging.getLogger("taproot-swap-integration-test")


def manager_for_watcher(
    swap: SwapData, *, confirmed=True, amount=ONCHAIN_AMOUNT, scriptpubkey=None,
):
    funding_tx, funding_txout, watched = make_funding(
        swap, amount=amount, scriptpubkey=scriptpubkey,
    )
    swap.funding_txid = None
    swap._funding_prevout = None
    tx_height = SimpleNamespace(conf=1 if confirmed else 0)
    adb = SimpleNamespace(
        get_addr_outputs=lambda _address: {watched.prevout: watched},
        get_transaction=lambda txid: funding_tx if txid == funding_tx.txid() else None,
        get_tx_height=lambda _txid: tx_height,
        is_up_to_date=lambda: True,
    )
    manager = SwapManager.__new__(SwapManager)
    manager.logger = logger()
    manager.swaps_lock = threading.Lock()
    manager._swaps = {swap.payment_hash.hex(): swap}
    manager._swaps_by_funding_outpoint = {watched.prevout: swap}
    manager._swaps_by_lockup_address = {swap.lockup_address: swap}
    manager._prepayments = {}
    manager.invoices_to_pay = {swap.payment_hash.hex(): 0}
    manager.lnwatcher = SimpleNamespace(adb=adb, remove_callback=mock.Mock())
    manager.lnworker = SimpleNamespace(
        get_preimage=mock.Mock(return_value=swap.preimage),
        save_preimage=mock.Mock(),
        hold_invoice_callbacks={},
    )
    manager.network = SimpleNamespace(
        get_local_height=lambda: LOCKTIME - 1,
        config=SimpleNamespace(TEST_SWAPSERVER_REFUND=False),
    )
    manager.wallet = SimpleNamespace(
        txbatcher=SimpleNamespace(add_sweep_input=mock.Mock()),
    )
    manager.config = SimpleNamespace(FEE_POLICY_SWAPS="fixed:1")
    manager._add_or_reindex_swap = mock.Mock()
    async def discard_task(coro):
        coro.close()
    manager.taskgroup = SimpleNamespace(spawn=mock.AsyncMock(side_effect=discard_task))
    return manager, funding_txout, watched


def manager_for_cooperation(
    swap: SwapData, *, confirmed=True, height=LOCKTIME,
):
    funding_tx, funding_txout, watched = make_funding(swap)
    tx_height = SimpleNamespace(conf=1 if confirmed else 0)
    transactions = {funding_tx.txid(): funding_tx}

    def add_transaction(tx):
        transactions[tx.txid()] = tx
        return True

    adb = SimpleNamespace(
        get_addr_outputs=lambda _address: {watched.prevout: watched},
        get_transaction=lambda txid: transactions.get(txid),
        get_tx_height=lambda _txid: tx_height,
        add_transaction=mock.Mock(side_effect=add_transaction),
        is_up_to_date=lambda: True,
    )
    manager = SwapManager.__new__(SwapManager)
    manager.logger = logger()
    manager.swaps_lock = threading.Lock()
    manager._swaps = {swap.payment_hash.hex(): swap}
    manager._swaps_by_funding_outpoint = {watched.prevout: swap}
    manager._swaps_by_lockup_address = {swap.lockup_address: swap}
    manager._prepayments = {}
    manager._musig_sessions = {}
    manager.invoices_to_pay = {swap.payment_hash.hex(): 0}
    manager.lnwatcher = SimpleNamespace(adb=adb, remove_callback=mock.Mock())
    manager.lnworker = SimpleNamespace(
        get_preimage=mock.Mock(return_value=swap.preimage),
        save_preimage=mock.Mock(),
        get_payment_status=mock.Mock(return_value=PR_UNPAID),
        get_payments=mock.Mock(return_value={}),
        inflight_payments=set(),
        hold_invoice_callbacks={},
    )
    manager.network = SimpleNamespace(
        get_local_height=lambda: height,
        broadcast_transaction=mock.AsyncMock(),
        config=SimpleNamespace(TEST_SWAPSERVER_REFUND=False),
    )
    manager.wallet = SimpleNamespace(
        get_receiving_address=destination_address,
        adb=adb,
        txbatcher=SimpleNamespace(add_sweep_input=mock.Mock()),
    )
    manager.config = SimpleNamespace(FEE_POLICY_SWAPS="fixed:1")
    manager.get_fee_for_txbatcher = lambda: FEE
    manager._add_or_reindex_swap = mock.Mock()
    async def discard_task(coro):
        coro.close()
    manager.taskgroup = SimpleNamespace(spawn=mock.AsyncMock(side_effect=discard_task))
    return manager, funding_txout, watched


def unsigned_cooperative_tx(
    watched: PartialTxInput,
    funding_txout: TxOutput,
    *,
    destination=None,
    value=ONCHAIN_AMOUNT - FEE,
) -> PartialTransaction:
    txin = PartialTxInput(prevout=watched.prevout)
    txin.witness_utxo = funding_txout
    txin.script_sig = b""
    txin.nsequence = 0xffffffff - 2
    return PartialTransaction.from_io(
        [txin],
        [PartialTxOutput.from_address_and_value(
            destination or destination_address(), value,
        )],
        locktime=0,
        version=2,
        BIP69_sort=False,
    )


def copy_txin(txin: PartialTxInput) -> PartialTxInput:
    copied = PartialTxInput(prevout=txin.prevout)
    copied.script_sig = txin.script_sig
    copied.nsequence = txin.nsequence
    return copied


class TestCapabilities(ElectrumTestCase):
    async def test_http_capability_and_missing_field_legacy_fallback(self):
        response = {
            "htlcFirst": True,
            "protocols": [TAPROOT_SWAP_PROTOCOL, TAPROOT_COOPERATIVE_CAPABILITY],
            "pairs": {"BTC/BTC": {
                "fees": {
                    "percentage": 0.5,
                    "minerFees": {"baseAsset": {"mining_fee": 500}},
                },
                "limits": {
                    "minimal": 20_000,
                    "max_forward_amount": 1_000_000,
                    "max_reverse_amount": 1_000_000,
                },
            }},
        }
        sm = SimpleNamespace(update_pairs=mock.Mock())
        transport = SimpleNamespace(
            send_request_to_server=mock.AsyncMock(return_value=response),
            sm=sm,
            logger=logger(),
            _protocols=(),
        )
        await HttpTransport.get_pairs_just_once(transport)
        self.assertEqual(
            (TAPROOT_SWAP_PROTOCOL, TAPROOT_COOPERATIVE_CAPABILITY),
            transport._protocols,
        )
        self.assertIsInstance(sm.update_pairs.call_args.args[0], SwapFees)

        response.pop("protocols")
        await HttpTransport.get_pairs_just_once(transport)
        self.assertEqual((), transport._protocols)

    async def test_http_server_and_nostr_offer_advertise_capability(self):
        sm = SimpleNamespace(
            server_update_pairs=mock.Mock(),
            _max_forward=1_000_000,
            _max_reverse=1_000_000,
            _min_amount=20_000,
            percentage=Decimal("0.5"),
            mining_fee=500,
            is_server=True,
            server_claim_taproot_swap=mock.Mock(return_value={"claim": True}),
            server_refund_taproot_swap=mock.Mock(return_value={"refund": True}),
            config=SimpleNamespace(
                NOSTR_RELAYS="wss://relay.example", SWAPSERVER_ANN_POW_NONCE=0,
            ),
        )
        response = await HttpSwapServer.get_pairs(SimpleNamespace(sm=sm), None)
        self.assertEqual(
            [TAPROOT_SWAP_PROTOCOL, TAPROOT_COOPERATIVE_CAPABILITY],
            json.loads(response.body)["protocols"],
        )
        request = SimpleNamespace(json=mock.AsyncMock(return_value={"id": "swap"}))
        claim = await HttpSwapServer.claim_taproot_swap(SimpleNamespace(sm=sm), request)
        refund = await HttpSwapServer.refund_taproot_swap(SimpleNamespace(sm=sm), request)
        self.assertEqual({"claim": True}, json.loads(claim.body))
        self.assertEqual({"refund": True}, json.loads(refund.body))

        transport = SimpleNamespace(
            sm=sm,
            relay_manager=object(),
            nostr_private_key="nsec-test",
            logger=logger(),
            USER_STATUS_NIP38=NostrTransport.USER_STATUS_NIP38,
            NOSTR_EVENT_VERSION=NostrTransport.NOSTR_EVENT_VERSION,
            OFFER_UPDATE_INTERVAL_SEC=NostrTransport.OFFER_UPDATE_INTERVAL_SEC,
        )
        with mock.patch(
            "electrum.submarine_swaps.aionostr._add_event",
            new=mock.AsyncMock(return_value="event-id"),
        ) as publish:
            await NostrTransport.publish_offer(transport, sm)
        self.assertEqual(
            [TAPROOT_SWAP_PROTOCOL, TAPROOT_COOPERATIVE_CAPABILITY],
            json.loads(publish.await_args.kwargs["content"])["protocols"],
        )

        legacy_offer = SwapOffer(
            pairs=mock.Mock(), relays=[], pow_bits=0, server_pubkey="11" * 32,
            timestamp=0,
        )
        self.assertEqual((), legacy_offer.protocols)

    async def test_nostr_transport_removes_reply_envelope_before_schema_validation(self):
        transport = SimpleNamespace(
            config=SimpleNamespace(SWAPSERVER_NPUB="npub-test"),
            dm_replies={},
            logger=logger(),
            relays=(),
            send_direct_message=mock.AsyncMock(return_value="event-id"),
        )
        with mock.patch(
            "electrum.submarine_swaps.aionostr.util.from_nip19",
            return_value={"object": bytes.fromhex("11" * 32)},
        ):
            request = asyncio.create_task(NostrTransport.send_request_to_server(
                transport, "createswap", {"value": 1},
            ))
            await asyncio.sleep(0)
            transport.dm_replies[("11" * 32, "event-id")].set_result({
                "reply_to": "event-id", "result": True,
            })
            response = await request
        self.assertEqual({"result": True}, response)


class TestNegotiation(ElectrumTestCase):
    @staticmethod
    def creation_manager():
        manager = SwapManager.__new__(SwapManager)
        manager.logger = logger()
        manager.network = SimpleNamespace(
            get_local_height=lambda: LOCAL_HEIGHT,
            blockchain=lambda: SimpleNamespace(is_tip_stale=lambda: False),
        )
        manager.swaps_lock = threading.Lock()
        manager._swaps = {}
        manager._swaps_by_funding_outpoint = {}
        manager._swaps_by_lockup_address = {}
        manager._prepayments = {}
        manager.mining_fee = FEE
        stored_swaps = {}
        manager.wallet = SimpleNamespace(
            db=SimpleNamespace(get_dict=lambda _key: stored_swaps),
            get_receiving_address=destination_address,
        )
        manager.lnwatcher = SimpleNamespace()
        manager.add_lnwatcher_callback = mock.Mock()
        manager._sanity_check_swap_costs = mock.Mock()
        manager.is_initialized = asyncio.Event()
        manager.is_initialized.set()
        lnaddr = SimpleNamespace(get_min_final_cltv_delta=lambda: 432)
        manager.lnworker = SimpleNamespace(
            add_payment_info_for_hold_invoice=mock.Mock(),
            get_payment_info=lambda payment_hash, direction: SimpleNamespace(
                payment_hash=payment_hash),
            get_bolt11_invoice=lambda **kwargs: (
                lnaddr, "lnfake:" + kwargs["payment_info"].payment_hash.hex()),
        )
        return manager

    @staticmethod
    def forward_response(request):
        user_pubkey = bytes.fromhex(request["refundPublicKey"])
        response_contract = TaprootSwapContract(
            direction=SwapDirection.FORWARD,
            payment_hash=PAYMENT_HASH,
            locktime=LOCKTIME,
            provider_pubkey=PROVIDER_PUBKEY,
            user_pubkey=user_pubkey,
        )
        return {
            "id": PAYMENT_HASH.hex(),
            "protocol": TAPROOT_SWAP_PROTOCOL,
            "acceptZeroConf": False,
            "preimageHash": PAYMENT_HASH.hex(),
            "claimPublicKey": PROVIDER_PUBKEY.hex(),
            "timeoutBlockHeight": LOCKTIME,
            "address": response_contract.address(),
            "swapTree": response_contract.serialized_tree(),
            "expectedAmount": ONCHAIN_AMOUNT,
        }

    async def test_forward_contract_verified_and_persisted(self):
        manager = self.creation_manager()

        async def send(_method, request):
            self.assertEqual(TAPROOT_SWAP_PROTOCOL, request["protocol"])
            return self.forward_response(request)

        swap, _invoice = await manager.request_normal_swap(
            transport=SimpleNamespace(
                protocols=(TAPROOT_SWAP_PROTOCOL, TAPROOT_COOPERATIVE_CAPABILITY),
                send_request_to_server=send,
            ),
            lightning_amount_sat=LIGHTNING_AMOUNT,
            expected_onchain_amount_sat=ONCHAIN_AMOUNT,
        )
        self.assertEqual(TAPROOT_SWAP_PROTOCOL, swap.protocol)
        self.assertEqual(PROVIDER_PUBKEY, swap.their_pubkey)
        self.assertTrue(swap.is_cooperative)
        restored = manager.get_taproot_contract(swap)
        self.assertIs(SwapDirection.FORWARD, restored.direction)
        self.assertEqual(PROVIDER_PUBKEY, restored.provider_pubkey)
        self.assertEqual(swap.redeem_script, restored.output_script)
        self.assertIs(swap, manager._swaps[PAYMENT_HASH.hex()])

        manager = self.creation_manager()

        branch_a_swap, _invoice = await manager.request_normal_swap(
            transport=SimpleNamespace(
                protocols=(TAPROOT_SWAP_PROTOCOL,), send_request_to_server=send,
            ),
            lightning_amount_sat=LIGHTNING_AMOUNT,
            expected_onchain_amount_sat=ONCHAIN_AMOUNT,
        )
        self.assertFalse(branch_a_swap.is_cooperative)

    async def test_forward_tampering_rejected_before_persistence(self):
        for tamper in (
            "tree", "protocol", "zero-conf", "mixed-schema", "extra-field", "id", "key",
            "address", "amount", "locktime",
        ):
            with self.subTest(tamper=tamper):
                manager = self.creation_manager()

                async def send(_method, request, *, tamper=tamper):
                    response = self.forward_response(request)
                    if tamper == "tree":
                        response["swapTree"]["claimLeaf"]["output"] = "00"
                    elif tamper == "protocol":
                        response["protocol"] = None
                    elif tamper == "zero-conf":
                        response["acceptZeroConf"] = True
                    elif tamper == "mixed-schema":
                        response["redeemScript"] = "00"
                    elif tamper == "extra-field":
                        response["unknown"] = None
                    elif tamper == "id":
                        response["id"] = "00" * 32
                    elif tamper == "key":
                        response["claimPublicKey"] = USER_PUBKEY.hex()
                    elif tamper == "address":
                        response["address"] = contract(SwapDirection.REVERSE).address()
                    elif tamper == "amount":
                        response["expectedAmount"] = ONCHAIN_AMOUNT + 1
                    elif tamper == "locktime":
                        response["timeoutBlockHeight"] += 1
                    return response

                error_context = (
                    self.assertRaisesRegex(Exception, "fswap check failed")
                    if tamper == "amount" else self.assertRaises(SwapServerError)
                )
                with error_context:
                    await manager.request_normal_swap(
                        transport=SimpleNamespace(
                            protocols=(TAPROOT_SWAP_PROTOCOL, TAPROOT_COOPERATIVE_CAPABILITY),
                            send_request_to_server=send,
                        ),
                        lightning_amount_sat=LIGHTNING_AMOUNT,
                        expected_onchain_amount_sat=ONCHAIN_AMOUNT,
                    )
                self.assertEqual({}, manager._swaps)

    async def test_forward_locktime_rejected_before_hold_invoice_creation(self):
        manager = self.creation_manager()

        async def send(_method, request):
            response = self.forward_response(request)
            locktime = LOCAL_HEIGHT + 1
            response_contract = TaprootSwapContract(
                direction=SwapDirection.FORWARD,
                payment_hash=PAYMENT_HASH,
                locktime=locktime,
                provider_pubkey=PROVIDER_PUBKEY,
                user_pubkey=bytes.fromhex(request["refundPublicKey"]),
            )
            response.update({
                "timeoutBlockHeight": locktime,
                "address": response_contract.address(),
                "swapTree": response_contract.serialized_tree(),
            })
            return response

        with self.assertRaisesRegex(Exception, "locktime too close"):
            await manager.request_normal_swap(
                transport=SimpleNamespace(
                    protocols=(TAPROOT_SWAP_PROTOCOL,), send_request_to_server=send,
                ),
                lightning_amount_sat=LIGHTNING_AMOUNT,
                expected_onchain_amount_sat=ONCHAIN_AMOUNT,
            )
        manager.lnworker.add_payment_info_for_hold_invoice.assert_not_called()
        self.assertEqual({}, manager._swaps)

    async def test_legacy_schema_fallback_and_unsolicited_taproot_rejection(self):
        manager = self.creation_manager()

        async def send(_method, request):
            self.assertNotIn("protocol", request)
            user_pubkey = bytes.fromhex(request["refundPublicKey"])
            script = _construct_swap_scriptcode(
                payment_hash=PAYMENT_HASH,
                locktime=LOCKTIME,
                refund_pubkey=user_pubkey,
                claim_pubkey=PROVIDER_PUBKEY,
            )
            return {
                "preimageHash": PAYMENT_HASH.hex(),
                "expectedAmount": ONCHAIN_AMOUNT,
                "timeoutBlockHeight": LOCKTIME,
                "address": bitcoin.script_to_p2wsh(script),
                "redeemScript": script.hex(),
            }

        swap, _invoice = await manager.request_normal_swap(
            transport=SimpleNamespace(protocols=(), send_request_to_server=send),
            lightning_amount_sat=LIGHTNING_AMOUNT,
            expected_onchain_amount_sat=ONCHAIN_AMOUNT,
        )
        self.assertIsNone(swap.protocol)
        self.assertIsNone(swap.their_pubkey)

        manager = self.creation_manager()

        async def unsolicited(_method, request):
            response = await send(_method, request)
            response["swapTree"] = {}
            return response

        with self.assertRaises(SwapServerError):
            await manager.request_normal_swap(
                transport=SimpleNamespace(protocols=(), send_request_to_server=unsolicited),
                lightning_amount_sat=LIGHTNING_AMOUNT,
                expected_onchain_amount_sat=ONCHAIN_AMOUNT,
            )
        self.assertEqual({}, manager._swaps)

    async def test_reverse_contract_and_mandatory_prepay_verify_before_persistence(self):
        for tamper in (
            None, "tree", "missing-prepay", "same-hash", "zero-conf", "extra-field",
        ):
            with self.subTest(tamper=tamper):
                manager = self.creation_manager()
                fee_hash = b"\xbb" * 32
                main_hash = None

                def check_invoice(encoded, *, tamper=tamper, fee_hash=fee_hash):
                    nonlocal main_hash
                    if encoded == "fee-invoice":
                        return SimpleNamespace(
                            paymenthash=main_hash if tamper == "same-hash" else fee_hash,
                            get_amount_sat=lambda: 1_000,
                        )
                    main_hash = bytes.fromhex(encoded.split(":")[1])
                    return SimpleNamespace(
                        paymenthash=main_hash,
                        get_amount_sat=lambda: LIGHTNING_AMOUNT - 1_000,
                    )

                async def pay_invoice(_invoice, manager=manager, **_kwargs):
                    if manager._swaps:
                        next(iter(manager._swaps.values())).funding_txid = "11" * 32
                    return True, []

                manager.lnworker._check_bolt11_invoice = check_invoice
                manager.lnworker.pay_invoice = pay_invoice

                async def send(_method, request, *, tamper=tamper):
                    payment_hash = bytes.fromhex(request["preimageHash"])
                    user_pubkey = bytes.fromhex(request["claimPublicKey"])
                    response_contract = TaprootSwapContract(
                        direction=SwapDirection.REVERSE,
                        payment_hash=payment_hash,
                        locktime=LOCKTIME,
                        provider_pubkey=PROVIDER_PUBKEY,
                        user_pubkey=user_pubkey,
                    )
                    response = {
                        "id": payment_hash.hex(),
                        "protocol": TAPROOT_SWAP_PROTOCOL,
                        "acceptZeroConf": False,
                        "invoice": "lnfake:" + payment_hash.hex(),
                        "minerFeeInvoice": "fee-invoice",
                        "refundPublicKey": PROVIDER_PUBKEY.hex(),
                        "lockupAddress": response_contract.address(),
                        "swapTree": response_contract.serialized_tree(),
                        "timeoutBlockHeight": LOCKTIME,
                        "onchainAmount": ONCHAIN_AMOUNT,
                    }
                    if tamper == "tree":
                        response["swapTree"]["refundLeaf"]["output"] = "00"
                    elif tamper == "missing-prepay":
                        response["minerFeeInvoice"] = None
                    elif tamper == "zero-conf":
                        response["acceptZeroConf"] = True
                    elif tamper == "extra-field":
                        response["unknown"] = None
                    return response

                with mock.patch.object(Invoice, "from_bech32", return_value=SimpleNamespace()):
                    if tamper is None:
                        await manager.reverse_swap(
                            transport=SimpleNamespace(
                                protocols=(TAPROOT_SWAP_PROTOCOL, TAPROOT_COOPERATIVE_CAPABILITY),
                                send_request_to_server=send,
                            ),
                            lightning_amount_sat=LIGHTNING_AMOUNT,
                            expected_onchain_amount_sat=ONCHAIN_AMOUNT,
                            prepayment_sat=1_000,
                        )
                        [swap] = manager._swaps.values()
                        self.assertEqual(fee_hash, swap.prepay_hash)
                        restored = manager.get_taproot_contract(swap)
                        self.assertIs(SwapDirection.REVERSE, restored.direction)
                        self.assertEqual(PROVIDER_PUBKEY, restored.provider_pubkey)
                        self.assertEqual(swap.redeem_script, restored.output_script)
                        self.assertTrue(swap.is_cooperative)
                    else:
                        with self.assertRaises(SwapServerError):
                            await manager.reverse_swap(
                                transport=SimpleNamespace(
                                    protocols=(TAPROOT_SWAP_PROTOCOL, TAPROOT_COOPERATIVE_CAPABILITY),
                                    send_request_to_server=send,
                                ),
                                lightning_amount_sat=LIGHTNING_AMOUNT,
                                expected_onchain_amount_sat=ONCHAIN_AMOUNT,
                                prepayment_sat=1_000,
                            )
                        self.assertEqual({}, manager._swaps)
                await asyncio.sleep(0)

    async def test_reverse_legacy_response_downgrade(self):
        manager = self.creation_manager()
        fee_hash = b"\xbb" * 32

        def check_invoice(encoded):
            payment_hash = bytes.fromhex(encoded.split(":")[1]) if encoded.startswith("main:") else fee_hash
            amount = LIGHTNING_AMOUNT - 1_000 if encoded.startswith("main:") else 1_000
            return SimpleNamespace(paymenthash=payment_hash, get_amount_sat=lambda: amount)

        async def send(_method, request):
            self.assertNotIn("protocol", request)
            payment_hash = bytes.fromhex(request["preimageHash"])
            script = _construct_swap_scriptcode(
                payment_hash=payment_hash,
                locktime=LOCKTIME,
                refund_pubkey=PROVIDER_PUBKEY,
                claim_pubkey=bytes.fromhex(request["claimPublicKey"]),
            )
            return {
                "id": payment_hash.hex(),
                "invoice": "main:" + payment_hash.hex(),
                "minerFeeInvoice": "fee",
                "lockupAddress": bitcoin.script_to_p2wsh(script),
                "redeemScript": script.hex(),
                "timeoutBlockHeight": LOCKTIME,
                "onchainAmount": ONCHAIN_AMOUNT,
            }

        async def pay_invoice(_invoice, **_kwargs):
            next(iter(manager._swaps.values())).funding_txid = "11" * 32
            return True, []

        manager.lnworker._check_bolt11_invoice = check_invoice
        manager.lnworker.pay_invoice = pay_invoice
        with mock.patch.object(Invoice, "from_bech32", return_value=SimpleNamespace()):
            await manager.reverse_swap(
                transport=SimpleNamespace(protocols=(), send_request_to_server=send),
                lightning_amount_sat=LIGHTNING_AMOUNT,
                expected_onchain_amount_sat=ONCHAIN_AMOUNT,
                prepayment_sat=1_000,
            )
        [swap] = manager._swaps.values()
        self.assertIsNone(swap.protocol)
        self.assertIsNone(swap.their_pubkey)
        await asyncio.sleep(0)

    def test_provider_creation_schemas_for_both_directions(self):
        actual_manager = self.creation_manager()
        actual_manager._get_send_amount = mock.Mock(return_value=ONCHAIN_AMOUNT)
        created = actual_manager.create_reverse_swap(
            lightning_amount_sat=LIGHTNING_AMOUNT,
            their_pubkey=USER_PUBKEY,
            is_taproot=True,
        )
        self.assertTrue(created.is_cooperative)

        manager = SwapManager.__new__(SwapManager)
        forward = make_swap(direction=SwapDirection.FORWARD, is_provider=True)
        manager.create_reverse_swap = mock.Mock(return_value=forward)
        response = manager.server_create_normal_swap({
            "protocol": TAPROOT_SWAP_PROTOCOL,
            "invoiceAmount": LIGHTNING_AMOUNT,
            "refundPublicKey": USER_PUBKEY.hex(),
        })
        self.assertEqual(TAPROOT_SWAP_PROTOCOL, response["protocol"])
        self.assertNotIn("redeemScript", response)
        self.assertFalse(response["acceptZeroConf"])

        self.assertNotIn("refundAddress", response)
        self.assertNotIn("refundValue", response)

        reverse = make_swap(direction=SwapDirection.REVERSE, is_provider=True)
        manager.create_normal_swap = mock.Mock(return_value=(reverse, "main", "prepay"))
        response = manager.server_create_swap({
            "protocol": TAPROOT_SWAP_PROTOCOL,
            "type": "reversesubmarine",
            "pairId": "BTC/BTC",
            "invoiceAmount": LIGHTNING_AMOUNT,
            "preimageHash": PAYMENT_HASH.hex(),
            "claimPublicKey": USER_PUBKEY.hex(),
        })
        self.assertEqual("prepay", response["minerFeeInvoice"])
        self.assertFalse(response["acceptZeroConf"])
        self.assertNotIn("redeemScript", response)

        self.assertNotIn("claimAddress", response)
        self.assertNotIn("claimValue", response)

        legacy_script = _construct_swap_scriptcode(
            payment_hash=PAYMENT_HASH,
            locktime=LOCKTIME,
            refund_pubkey=PROVIDER_PUBKEY,
            claim_pubkey=USER_PUBKEY,
        )
        reverse.protocol = None
        reverse.their_pubkey = None
        reverse.redeem_script = legacy_script
        reverse.lockup_address = bitcoin.script_to_p2wsh(legacy_script)
        manager.create_normal_swap = mock.Mock(return_value=(reverse, "main", "prepay"))
        response = manager.server_create_swap({
            "type": "reversesubmarine",
            "pairId": "BTC/BTC",
            "invoiceAmount": LIGHTNING_AMOUNT,
            "preimageHash": PAYMENT_HASH.hex(),
            "claimPublicKey": USER_PUBKEY.hex(),
        })
        self.assertEqual(legacy_script.hex(), response["redeemScript"])
        self.assertNotIn("protocol", response)
        self.assertNotIn("swapTree", response)


class TestPersistenceInvoicesAndSettlement(ElectrumTestCase):
    def test_contract_roles_survive_reload_and_tampering_fails(self):
        for direction in SwapDirection:
            for is_provider in (False, True):
                with self.subTest(direction=direction, is_provider=is_provider):
                    swap = make_swap(direction=direction, is_provider=is_provider)
                    restored = SwapData(**json.loads(json.dumps(swap, cls=MyEncoder)))
                    restored._payment_hash = PAYMENT_HASH
                    self.assertEqual(contract(direction), SwapManager._validate_taproot_swap(restored))

        restored.redeem_script = bytes(34)
        with self.assertRaisesRegex(ValueError, "output script"):
            SwapManager._validate_taproot_swap(restored)

    def test_legacy_swap_data_deserializes_with_defaults(self):
        legacy = json.loads(json.dumps(make_swap(
            direction=SwapDirection.FORWARD, is_provider=False,
        ), cls=MyEncoder))
        for field in (
            "protocol", "their_pubkey", "is_provider", "cooperative_tx",
            "is_cooperative", "refund_cancelled",
        ):
            legacy.pop(field)
        restored = SwapData(**legacy)
        self.assertIsNone(restored.protocol)
        self.assertIsNone(restored.their_pubkey)
        self.assertFalse(restored.is_provider)
        self.assertFalse(restored.is_cooperative)
        self.assertFalse(restored.refund_cancelled)

    async def test_branch_a_taproot_swap_skips_cooperation_and_uses_script_path(self):
        swap = make_swap(
            direction=SwapDirection.REVERSE, is_provider=False, is_cooperative=False,
        )
        SwapManager._validate_taproot_swap(swap)
        manager, _funding, _watched = manager_for_watcher(swap)
        await manager._claim_swap(swap)
        manager.taskgroup.spawn.assert_not_awaited()
        manager.wallet.txbatcher.add_sweep_input.assert_called_once()

        provider_swap = make_swap(
            direction=SwapDirection.REVERSE, is_provider=True, is_cooperative=False,
        )
        provider, funding_txout, watched = manager_for_cooperation(provider_swap)
        tx = unsigned_cooperative_tx(watched, funding_txout)
        with self.assertRaisesRegex(ValueError, "unknown"):
            provider.server_claim_taproot_swap({
                "id": PAYMENT_HASH.hex(),
                "sessionId": (b"\x52" * 32).hex(),
                "transaction": tx.serialize_to_network(include_sigs=False),
                "preimage": PREIMAGE.hex(),
            })

    def test_taproot_swap_restarts_and_reindexes(self):
        swap = make_swap(direction=SwapDirection.FORWARD, is_provider=False)
        restored = SwapData(**json.loads(json.dumps(swap, cls=MyEncoder)))
        lnworker = SimpleNamespace(
            lnwatcher=SimpleNamespace(),
            get_preimage=mock.Mock(return_value=None),
            register_hold_invoice=mock.Mock(),
        )
        wallet = SimpleNamespace(
            config=SimpleNamespace(),
            db=SimpleNamespace(get_dict=lambda _key: {PAYMENT_HASH.hex(): restored}),
        )
        manager = SwapManager(wallet=wallet, lnworker=lnworker)
        self.assertIs(restored, manager._swaps_by_lockup_address[restored.lockup_address])
        self.assertEqual(PAYMENT_HASH, restored.payment_hash)
        self.assertTrue(restored.is_cooperative)
        lnworker.register_hold_invoice.assert_called_once_with(
            PAYMENT_HASH, manager.hold_invoice_callback,
        )

    def test_add_invoice_preserves_ownership_and_two_phase_hold_semantics(self):
        swap = make_swap(direction=SwapDirection.FORWARD, is_provider=True)
        swap.preimage = PREIMAGE
        invoice = SimpleNamespace(
            rhash=PAYMENT_HASH.hex(),
            get_amount_sat=lambda: LIGHTNING_AMOUNT,
            get_id=lambda: "invoice-id",
        )
        manager = SwapManager.__new__(SwapManager)
        manager.swaps_lock = threading.Lock()
        manager._swaps = {PAYMENT_HASH.hex(): swap}
        manager.invoices_to_pay = {}
        manager.wallet = SimpleNamespace(
            get_invoice=lambda _invoice_id: None,
            save_invoice=mock.Mock(),
        )
        with mock.patch.object(Invoice, "from_bech32", return_value=invoice):
            manager.server_add_swap_invoice({
                "invoice": "hold-invoice",
                "refundPublicKey": USER_PUBKEY.hex(),
            })
        manager.wallet.save_invoice.assert_called_once_with(invoice)
        self.assertEqual({PAYMENT_HASH.hex(): 0}, manager.invoices_to_pay)
        self.assertIsNone(swap.funding_txid)

        manager.invoices_to_pay = {}
        manager.wallet.save_invoice.reset_mock()
        with mock.patch.object(Invoice, "from_bech32", return_value=invoice):
            with self.assertRaisesRegex(ValueError, "public key"):
                manager.server_add_swap_invoice({
                    "invoice": "hold-invoice",
                    "refundPublicKey": PROVIDER_PUBKEY.hex(),
                })
        manager.wallet.save_invoice.assert_not_called()

    def test_all_role_witnesses_use_claim_or_refund_leaf(self):
        signature = b"\x44" * 64
        for direction in SwapDirection:
            for is_provider in (False, True):
                with self.subTest(direction=direction, is_provider=is_provider):
                    swap = make_swap(direction=direction, is_provider=is_provider)
                    _funding, funding_txout, watched = make_funding(swap)
                    watched.witness_utxo = funding_txout
                    txin, locktime = SwapManager.create_claim_txin(txin=watched, swap=swap)
                    leaf = SwapLeaf.CLAIM if swap.is_reverse else SwapLeaf.REFUND
                    script, control = contract(direction).script_path(leaf)
                    txin.witness = txin.make_witness(signature)
                    expected = (
                        [signature, PREIMAGE, script, control]
                        if swap.is_reverse else [signature, script, control]
                    )
                    self.assertEqual(expected, list(txin.witness_elements()))
                    self.assertEqual(None if swap.is_reverse else LOCKTIME, locktime)
                    self.assertEqual(1 if swap.is_reverse else 0xffffffff - 2, txin.nsequence)
                    self.assertIsNotNone(txin.tap_script_signing_data)

                    spend = PartialTransaction.from_io(
                        [txin],
                        [PartialTxOutput(scriptpubkey=b"\x51", value=ONCHAIN_AMOUNT - 1_000)],
                        locktime=locktime or 0,
                        BIP69_sort=False,
                    )
                    txin.witness = txin.make_witness(
                        spend.sign_txin(0, swap.privkey)
                    )
                    self.assertTrue(txin.is_complete())

    async def test_reverse_client_claim_waits_for_exact_confirmed_funding(self):
        for confirmed, amount, scriptpubkey, should_claim in (
            (False, ONCHAIN_AMOUNT, None, False),
            (True, ONCHAIN_AMOUNT + 1, None, False),
            (True, ONCHAIN_AMOUNT, bytes(34), False),
            (True, ONCHAIN_AMOUNT, None, True),
        ):
            with self.subTest(confirmed=confirmed, amount=amount, scriptpubkey=scriptpubkey):
                swap = make_swap(direction=SwapDirection.REVERSE, is_provider=False)
                manager, _funding, watched = manager_for_watcher(
                    swap, confirmed=confirmed, amount=amount, scriptpubkey=scriptpubkey,
                )
                await manager._claim_swap(swap)
                self.assertEqual(
                    should_claim, manager.taskgroup.spawn.await_count == 1,
                )
                manager.wallet.txbatcher.add_sweep_input.assert_not_called()
                if not should_claim:
                    manager.lnworker.get_preimage.assert_not_called()
                    self.assertIsNone(swap.funding_txid)
                if should_claim:
                    self.assertEqual(swap.redeem_script, watched.witness_utxo.scriptpubkey)

    async def test_local_spend_suppresses_competing_claim(self):
        swap = make_swap(direction=SwapDirection.REVERSE, is_provider=False)
        manager, _funding, watched = manager_for_watcher(swap)
        watched.spent_height = TX_HEIGHT_LOCAL
        watched.spent_txid = "44" * 32
        await manager._claim_swap(swap)
        manager.wallet.txbatcher.add_sweep_input.assert_not_called()
        self.assertEqual(watched.spent_txid, swap.spending_txid)

    def test_taproot_funding_output_uses_validated_output_script(self):
        swap = make_swap(direction=SwapDirection.FORWARD, is_provider=False)
        manager = SwapManager.__new__(SwapManager)
        output = manager.create_funding_output(swap)
        self.assertEqual(swap.redeem_script, output.scriptpubkey)
        self.assertEqual(swap.onchain_amount, output.value)


class TestCooperativeSettlement(ElectrumTestCase):
    @staticmethod
    def _round_one_context(
        *, direction=SwapDirection.REVERSE, confirmed=True, session_byte=b"\x12",
    ):
        swap = make_swap(direction=direction, is_provider=True)
        manager, funding_txout, watched = manager_for_cooperation(
            swap, confirmed=confirmed,
        )
        tx = unsigned_cooperative_tx(watched, funding_txout)
        request = {
            "id": PAYMENT_HASH.hex(),
            "sessionId": (session_byte * 32).hex(),
            "transaction": tx.serialize_to_network(include_sigs=False),
        }
        if direction is SwapDirection.REVERSE:
            request["preimage"] = PREIMAGE.hex()
        return manager, swap, tx, request

    def _start_session(self, *, direction=SwapDirection.REVERSE):
        manager, swap, tx, request = self._round_one_context(direction=direction)
        handler = (
            manager.server_claim_taproot_swap
            if direction is SwapDirection.REVERSE
            else manager.server_refund_taproot_swap
        )
        response = handler(request)
        _checked_tx, msg32 = manager._parse_cooperative_transaction(
            swap, request["transaction"], require_confirmed=True,
        )
        client = MuSig2Session.create(
            contract=contract(direction),
            local_seckey=USER_SECKEY,
            msg32=msg32,
            session_id32=bytes.fromhex(request["sessionId"]),
        )
        client_partial = client.sign_partial(bytes.fromhex(response["pubNonce"]))
        final = {
            "id": PAYMENT_HASH.hex(),
            "sessionId": request["sessionId"],
            "pubNonce": client.public_nonce.hex(),
            "partialSignature": client_partial.hex(),
        }
        return manager, swap, tx, request, response, final

    async def test_reverse_claim_and_forward_refund_end_to_end(self):
        for direction in SwapDirection:
            with self.subTest(direction=direction):
                client_swap = make_swap(direction=direction, is_provider=False)
                provider_swap = make_swap(direction=direction, is_provider=True)
                client_manager, _client_out, watched = manager_for_cooperation(client_swap)
                provider_manager, _provider_out, _provider_watched = manager_for_cooperation(
                    provider_swap,
                )
                requests = []

                async def send(method, request):
                    requests.append(dict(request))
                    handler = (
                        provider_manager.server_claim_taproot_swap
                        if method == "claimtaprootswap"
                        else provider_manager.server_refund_taproot_swap
                    )
                    return handler(request)

                client_manager._send_cooperative_request = send
                signed_tx = await client_manager._create_cooperative_spend_tx(
                    client_swap, watched,
                )
                self.assertEqual([64], [
                    len(item) for item in signed_tx.inputs()[0].witness_elements()
                ])
                self.assertEqual(signed_tx.txid(), client_swap.spending_txid)
                self.assertEqual(signed_tx.serialize_to_network(), client_swap.cooperative_tx)
                self.assertEqual(signed_tx.serialize_to_network(), provider_swap.cooperative_tx)
                self.assertNotIn("destination", requests[0])
                self.assertNotIn("index", requests[0])
                self.assertEqual(
                    {"id", "sessionId", "transaction", "preimage"}
                    if direction is SwapDirection.REVERSE
                    else {"id", "sessionId", "transaction"},
                    set(requests[0]),
                )
                if direction is SwapDirection.REVERSE:
                    provider_manager.lnworker.save_preimage.assert_called_once_with(
                        PAYMENT_HASH, PREIMAGE, mark_as_public=True,
                    )

    def test_canonical_unsigned_transaction_policy(self):
        swap = make_swap(direction=SwapDirection.REVERSE, is_provider=True)
        manager, funding_txout, watched = manager_for_cooperation(swap)

        def check(tx, **kwargs):
            return manager._parse_cooperative_transaction(
                swap,
                tx.serialize_to_network(include_sigs=False),
                expected_destination=destination_address(),
                expected_value=ONCHAIN_AMOUNT - FEE,
                require_confirmed=True,
                **kwargs,
            )

        valid = unsigned_cooperative_tx(watched, funding_txout)
        checked, msg32 = check(valid)
        self.assertEqual(32, len(msg32))
        self.assertEqual(valid.serialize_to_network(include_sigs=False),
                         checked.serialize_to_network(include_sigs=False))

        arbitrary = unsigned_cooperative_tx(
            watched,
            funding_txout,
            destination=alternate_destination_address(),
            value=ONCHAIN_AMOUNT - FEE - 1,
        )
        arbitrary_raw = arbitrary.serialize_to_network(include_sigs=False)
        checked, _msg32 = manager._parse_cooperative_transaction(
            swap, arbitrary_raw, require_confirmed=True,
        )
        self.assertEqual(alternate_destination_address(), checked.outputs()[0].address)
        response = manager.server_claim_taproot_swap({
            "id": PAYMENT_HASH.hex(),
            "sessionId": (b"\x51" * 32).hex(),
            "transaction": arbitrary_raw,
            "preimage": PREIMAGE.hex(),
        })
        self.assertEqual(arbitrary_raw, response["transaction"])
        manager._musig_sessions.clear()

        mutations = {
            "wrong txid": lambda tx: setattr(
                tx.inputs()[0], "prevout", TxOutpoint(txid=b"\xff" * 32, out_idx=0)),
            "wrong output index": lambda tx: setattr(
                tx.inputs()[0], "prevout",
                TxOutpoint(txid=tx.inputs()[0].prevout.txid, out_idx=1)),
            "sequence": lambda tx: setattr(tx.inputs()[0], "nsequence", 1),
            "locktime": lambda tx: setattr(tx, "locktime", 1),
            "version": lambda tx: setattr(tx, "version", 1),
            "destination": lambda tx: setattr(
                tx.outputs()[0], "scriptpubkey", bytes.fromhex("6a")),
            "value": lambda tx: setattr(tx.outputs()[0], "value", ONCHAIN_AMOUNT - FEE - 1),
            "zero fee": lambda tx: setattr(tx.outputs()[0], "value", ONCHAIN_AMOUNT),
            "negative fee": lambda tx: setattr(tx.outputs()[0], "value", ONCHAIN_AMOUNT + 1),
            "high fee": lambda tx: setattr(
                tx.outputs()[0], "value",
                ONCHAIN_AMOUNT - (COOPERATIVE_SWAP_TX_SIZE * 600_000 // 1000) - 1),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                tx = unsigned_cooperative_tx(watched, funding_txout)
                mutate(tx)
                with self.assertRaises(ValueError):
                    check(tx)

        signed = unsigned_cooperative_tx(watched, funding_txout)
        signed.inputs()[0].witness = bitcoin.construct_witness([b"signed"])
        with self.assertRaisesRegex(ValueError, "unsigned"):
            manager._parse_cooperative_transaction(
                swap,
                signed.serialize_to_network(),
                require_confirmed=True,
            )

        for name, inputs, outputs in (
            ("two inputs", [valid.inputs()[0], copy_txin(valid.inputs()[0])], valid.outputs()),
            ("two outputs", valid.inputs(), [valid.outputs()[0], valid.outputs()[0]]),
        ):
            with self.subTest(name=name):
                tx = PartialTransaction.from_io(
                    inputs, outputs, locktime=0, version=2, BIP69_sort=False,
                )
                with self.assertRaisesRegex(ValueError, "shape"):
                    check(tx)

    def test_expected_destination_value_and_exact_funding_output(self):
        swap = make_swap(direction=SwapDirection.REVERSE, is_provider=True)
        manager, funding_txout, watched = manager_for_cooperation(swap)
        tx = unsigned_cooperative_tx(watched, funding_txout)
        raw_tx = tx.serialize_to_network(include_sigs=False)
        with self.assertRaises(ValueError):
            manager._parse_cooperative_transaction(
                swap, raw_tx, expected_destination=contract(SwapDirection.REVERSE).address(),
                expected_value=ONCHAIN_AMOUNT - FEE, require_confirmed=True,
            )
        with self.assertRaises(ValueError):
            manager._parse_cooperative_transaction(
                swap, raw_tx, expected_destination=destination_address(),
                expected_value=ONCHAIN_AMOUNT - FEE + 1, require_confirmed=True,
            )

        for field in ("value", "script"):
            with self.subTest(field=field):
                swap = make_swap(direction=SwapDirection.REVERSE, is_provider=True)
                manager, funding_txout, watched = manager_for_cooperation(swap)
                funding_tx = manager.lnwatcher.adb.get_transaction(swap.funding_txid)
                if field == "value":
                    funding_tx.outputs()[0].value += 1
                else:
                    funding_tx.outputs()[0].scriptpubkey = bytes.fromhex("6a")
                tx = unsigned_cooperative_tx(watched, funding_txout)
                with self.assertRaisesRegex(ValueError, "funding output"):
                    manager._parse_cooperative_transaction(
                        swap, tx.serialize_to_network(include_sigs=False),
                        require_confirmed=True,
                    )

    async def test_unconfirmed_reverse_and_preimage_mismatch_are_rejected(self):
        manager, _swap, _tx, request = self._round_one_context(confirmed=False)
        with self.assertRaisesRegex(ValueError, "not confirmed"):
            manager.server_claim_taproot_swap(request)
        request["preimage"] = (b"\xbb" * 32).hex()
        manager.lnwatcher.adb.get_tx_height = lambda _txid: SimpleNamespace(conf=1)
        with self.assertRaisesRegex(ValueError, "preimage"):
            manager.server_claim_taproot_swap(request)

        client_swap = make_swap(direction=SwapDirection.REVERSE, is_provider=False)
        client_swap.preimage = b"\xbb" * 32
        client_manager, _funding, watched = manager_for_cooperation(client_swap)
        with self.assertRaisesRegex(ValueError, "preimage"):
            await client_manager._create_cooperative_spend_tx(client_swap, watched)

    def test_session_expiry_reuse_capacity_one_per_swap_and_schema(self):
        manager, swap, _tx, request, _response, final = self._start_session()
        with mock.patch(
            "electrum.submarine_swaps.time.monotonic",
            return_value=time.monotonic() + MUSIG_SESSION_TTL_SEC + 1,
        ):
            with self.assertRaisesRegex(ValueError, "expired"):
                manager.server_claim_taproot_swap(final)
        with self.assertRaisesRegex(ValueError, "already used"):
            manager.server_claim_taproot_swap(final)

        manager, _swap, _tx, _request, _response, final = self._start_session()
        manager.server_claim_taproot_swap(final)
        with self.assertRaisesRegex(ValueError, "already used"):
            manager.server_claim_taproot_swap(final)

        manager, swap, _tx, request, _response, _final = self._start_session()
        second = dict(request, sessionId=(b"\x13" * 32).hex())
        with self.assertRaisesRegex(ValueError, "active MuSig session"):
            manager.server_claim_taproot_swap(second)
        manager._musig_sessions.clear()
        manager._musig_sessions = {
            str(index): (time.monotonic() + 1000, None, object())
            for index in range(MUSIG_SESSION_MAX_ENTRIES)
        }
        with self.assertRaisesRegex(ValueError, "capacity"):
            manager.server_claim_taproot_swap(second)
        manager._musig_sessions.clear()
        with self.assertRaisesRegex(ValueError, "lowercase"):
            manager.server_claim_taproot_swap(dict(
                request, sessionId=(b"\xab" * 32).hex().upper(),
            ))
        for extra in ("destination", "index", "unexpected"):
            with self.subTest(extra=extra):
                bad_request = dict(request, sessionId=sha256(extra.encode()).hex())
                bad_request[extra] = destination_address() if extra == "destination" else 0
                with self.assertRaisesRegex(ValueError, "request fields"):
                    manager.server_claim_taproot_swap(bad_request)

    def test_forged_partial_mismatch_and_session_consumption(self):
        manager, _swap, _tx, _request, _response, final = self._start_session()
        final["partialSignature"] = bytes(32).hex()
        with self.assertRaisesRegex(ValueError, "partial signature"):
            manager.server_claim_taproot_swap(final)
        with self.assertRaisesRegex(ValueError, "already used"):
            manager.server_claim_taproot_swap(final)

        for missing_field in ("pubNonce", "partialSignature"):
            with self.subTest(missing_field=missing_field):
                manager, _swap, _tx, _request, _response, final = self._start_session()
                final.pop(missing_field)
                with self.assertRaisesRegex(ValueError, "request fields"):
                    manager.server_claim_taproot_swap(final)
                self.assertEqual({}, manager._musig_sessions)

        manager, _swap, _tx, _request, _response, final = self._start_session()
        final["pubNonce"] = (b"\x02" + b"\x00" * 32) * 2
        final["pubNonce"] = final["pubNonce"].hex()
        with self.assertRaises(ValueError):
            manager.server_claim_taproot_swap(final)
        with self.assertRaisesRegex(ValueError, "already used"):
            manager.server_claim_taproot_swap(final)

    async def test_client_rejects_forged_partial_final_signature_and_identity(self):
        for tamper in ("first identity", "partial", "final witness", "final identity"):
            with self.subTest(tamper=tamper):
                client_swap = make_swap(direction=SwapDirection.REVERSE, is_provider=False)
                provider_swap = make_swap(direction=SwapDirection.REVERSE, is_provider=True)
                client_manager, _client_out, watched = manager_for_cooperation(client_swap)
                provider_manager, _provider_out, _watched = manager_for_cooperation(provider_swap)
                calls = 0

                async def send(_method, request):
                    nonlocal calls
                    calls += 1
                    response = provider_manager.server_claim_taproot_swap(request)
                    if tamper == "first identity" and calls == 1:
                        response["transaction"] += "00"
                    elif tamper == "partial" and calls == 2:
                        response["partialSignature"] = bytes(32).hex()
                    elif tamper == "final witness" and calls == 2:
                        tx = Transaction(response["transaction"])
                        tx.inputs()[0].witness = bitcoin.construct_witness([bytes(64)])
                        response["transaction"] = tx.serialize_to_network()
                    elif tamper == "final identity" and calls == 2:
                        tx = Transaction(response["transaction"])
                        tx.outputs()[0].value -= 1
                        response["transaction"] = tx.serialize_to_network()
                    return response

                client_manager._send_cooperative_request = send
                with self.assertRaises(ValueError):
                    await client_manager._create_cooperative_spend_tx(client_swap, watched)
                self.assertIsNone(client_swap.cooperative_tx)

    def test_forward_refund_payment_state_checked_in_both_rounds(self):
        start_states = {
            "paid": lambda manager, swap: manager.lnworker.get_payment_status.configure_mock(
                return_value=PR_PAID),
            "inflight status": lambda manager, swap: manager.lnworker.get_payment_status.configure_mock(
                return_value=PR_INFLIGHT),
            "memory inflight": lambda manager, swap: manager.lnworker.inflight_payments.add(
                swap.payment_hash.hex()),
            "persisted HTLC": lambda manager, swap: manager.lnworker.get_payments.configure_mock(
                return_value={swap.payment_hash: [object()]}),
        }
        for name, set_state in start_states.items():
            with self.subTest(round="start", state=name):
                manager, swap, _tx, request = self._round_one_context(
                    direction=SwapDirection.FORWARD,
                )
                set_state(manager, swap)
                with self.assertRaises(ValueError):
                    manager.server_refund_taproot_swap(request)
                self.assertEqual({}, manager._musig_sessions)

            with self.subTest(round="finish", state=name):
                manager, swap, _tx, _request, _response, final = self._start_session(
                    direction=SwapDirection.FORWARD,
                )
                set_state(manager, swap)
                with self.assertRaises(ValueError):
                    manager.server_refund_taproot_swap(final)
                with self.assertRaisesRegex(ValueError, "already used"):
                    manager.server_refund_taproot_swap(final)

    async def test_forward_refund_and_payment_start_are_serialized(self):
        manager, swap, _tx, request = self._round_one_context(
            direction=SwapDirection.FORWARD,
        )
        payment_started = asyncio.Event()
        release_payment = asyncio.Event()

        async def pay_invoice(_invoice):
            payment_started.set()
            await release_payment.wait()
            return False, []

        manager.wallet.get_invoice = mock.Mock(return_value=object())
        manager.lnworker.pay_invoice = mock.AsyncMock(side_effect=pay_invoice)
        payment_task = asyncio.create_task(manager.pay_invoice(swap.payment_hash.hex()))
        await payment_started.wait()
        self.assertTrue(swap._lightning_payment_pending)
        with self.assertRaisesRegex(ValueError, "in flight"):
            manager.server_refund_taproot_swap(request)
        self.assertEqual({}, manager._musig_sessions)
        release_payment.set()
        await payment_task
        self.assertFalse(swap._lightning_payment_pending)

        response = manager.server_refund_taproot_swap(request)
        self.assertIn("pubNonce", response)
        self.assertTrue(swap.refund_cancelled)
        manager.lnworker.pay_invoice.reset_mock()
        manager.invoices_to_pay[swap.payment_hash.hex()] = 0
        await manager.pay_invoice(swap.payment_hash.hex())
        manager.lnworker.pay_invoice.assert_not_awaited()
        self.assertNotIn(swap.payment_hash.hex(), manager.invoices_to_pay)

    async def test_forward_client_waits_for_timeout(self):
        swap = make_swap(direction=SwapDirection.FORWARD, is_provider=False)
        manager, _funding, watched = manager_for_cooperation(
            swap, height=LOCKTIME - 1,
        )
        with self.assertRaisesRegex(ValueError, "timeout"):
            await manager._create_cooperative_spend_tx(swap, watched)

    async def test_timeout_refusal_and_error_use_script_fallback(self):
        for error in (
            SwapServerError("refused"), asyncio.TimeoutError(), ValueError("bad response"),
        ):
            with self.subTest(error=type(error).__name__):
                swap = make_swap(direction=SwapDirection.REVERSE, is_provider=False)
                manager, _funding, watched = manager_for_cooperation(swap)
                manager._create_cooperative_spend_tx = mock.AsyncMock(side_effect=error)
                manager._claim_swap = mock.AsyncMock()
                swap._coop_spend_pending = True
                await manager._cooperative_spend(swap, watched)
                self.assertTrue(swap._coop_spend_failed)
                self.assertFalse(swap._coop_spend_pending)
                manager._claim_swap.assert_awaited_once_with(swap)

    async def test_managed_task_spawn_failure_resets_pending_flag(self):
        swap = make_swap(direction=SwapDirection.REVERSE, is_provider=False)
        manager, _funding, _watched = manager_for_cooperation(swap)

        async def fail_spawn(coro):
            coro.close()
            raise RuntimeError("task group stopped")

        manager.taskgroup.spawn = mock.AsyncMock(side_effect=fail_spawn)
        with self.assertRaisesRegex(RuntimeError, "task group stopped"):
            await manager._claim_swap(swap)
        self.assertFalse(swap._coop_spend_pending)

    async def test_cooperative_response_wait_is_bounded_to_30_seconds(self):
        class Transport:
            def __init__(self):
                self.is_connected = asyncio.Event()
                self.is_connected.set()

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc_value, traceback):
                return None

            async def send_request_to_server(self, _method, _request):
                await asyncio.Event().wait()

        timeouts = []

        async def wait(awaitable, *, timeout):
            timeouts.append(timeout)
            if timeout == 15:
                return await awaitable
            awaitable.close()
            raise asyncio.TimeoutError

        manager = SimpleNamespace(create_transport=lambda: Transport())
        with mock.patch("electrum.submarine_swaps.wait_for2", new=wait):
            with self.assertRaisesRegex(SwapServerError, "did not reply"):
                await SwapManager._send_cooperative_request(manager, "method", {})
        self.assertEqual([15, 30], timeouts)

    async def test_local_competitor_suppressed_and_persisted_tx_rebroadcasts_after_restart(self):
        client_swap = make_swap(direction=SwapDirection.REVERSE, is_provider=False)
        provider_swap = make_swap(direction=SwapDirection.REVERSE, is_provider=True)
        client_manager, _client_out, watched = manager_for_cooperation(client_swap)
        provider_manager, _provider_out, _provider_watched = manager_for_cooperation(provider_swap)

        async def send(_method, request):
            return provider_manager.server_claim_taproot_swap(request)

        client_manager._send_cooperative_request = send
        signed_tx = await client_manager._create_cooperative_spend_tx(client_swap, watched)
        provider_manager.network.get_local_height = lambda: LOCKTIME - 1
        await provider_manager._claim_swap(provider_swap)
        provider_manager.network.broadcast_transaction.assert_awaited_once()
        watched.spent_height = TX_HEIGHT_LOCAL
        watched.spent_txid = "55" * 32
        client_manager.network.broadcast_transaction.reset_mock()
        await client_manager._claim_swap(client_swap)
        client_manager.network.broadcast_transaction.assert_not_awaited()

        watched.spent_txid = signed_tx.txid()
        client_manager.network.broadcast_transaction.reset_mock()
        await client_manager._claim_swap(client_swap)
        client_manager.network.broadcast_transaction.assert_awaited_once()
        rebroadcast = client_manager.network.broadcast_transaction.await_args.args[0]
        self.assertEqual(client_swap.cooperative_tx, rebroadcast.serialize_to_network())
        client_manager.taskgroup.spawn.assert_not_awaited()
        client_manager.wallet.txbatcher.add_sweep_input.assert_not_called()

        restored = SwapData(**json.loads(json.dumps(client_swap, cls=MyEncoder)))
        restored._payment_hash = PAYMENT_HASH
        SwapManager._validate_taproot_swap(restored)
        tampered = SwapData(**json.loads(json.dumps(restored, cls=MyEncoder)))
        tampered._payment_hash = PAYMENT_HASH
        tampered_tx = Transaction(tampered.cooperative_tx)
        tampered_tx.inputs()[0].witness = bitcoin.construct_witness([bytes(64)])
        tampered.cooperative_tx = tampered_tx.serialize_to_network()
        self.assertEqual(restored.spending_txid, tampered_tx.txid())
        with self.assertRaisesRegex(ValueError, "signature"):
            SwapManager._validate_taproot_swap(tampered)
        restored._funding_prevout = TxOutpoint(
            txid=bytes.fromhex(restored.funding_txid), out_idx=1,
        )
        with self.assertRaisesRegex(ValueError, "funding output"):
            SwapManager._validate_taproot_swap(restored)
        restored._funding_prevout = watched.prevout
        restart_manager = SimpleNamespace(
            network=SimpleNamespace(broadcast_transaction=mock.AsyncMock()),
            logger=logger(),
        )
        await SwapManager._rebroadcast_cooperative_spend(restart_manager, restored)
        restarted_tx = restart_manager.network.broadcast_transaction.await_args.args[0]
        self.assertEqual(restored.cooperative_tx, restarted_tx.serialize_to_network())
        self.assertEqual(restored.spending_txid, restarted_tx.txid())
