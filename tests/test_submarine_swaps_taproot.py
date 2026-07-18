import asyncio
import json
import logging
import threading
from decimal import Decimal
from types import SimpleNamespace
from unittest import mock

from electrum_ecc import ECPrivkey

from electrum import bitcoin
from electrum.address_synchronizer import TX_HEIGHT_LOCAL
from electrum.crypto import sha256
from electrum.invoices import Invoice
from electrum.plugins.swapserver.server import HttpSwapServer
from electrum.submarine_swaps import (
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
from electrum.taproot_swaps import SwapDirection, SwapLeaf, TaprootSwapContract
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


def contract(direction: SwapDirection, *, payment_hash=PAYMENT_HASH) -> TaprootSwapContract:
    return TaprootSwapContract(
        direction=direction,
        payment_hash=payment_hash,
        locktime=LOCKTIME,
        provider_pubkey=PROVIDER_PUBKEY,
        user_pubkey=USER_PUBKEY,
    )


def make_swap(*, direction: SwapDirection, is_provider: bool) -> SwapData:
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
    return manager, funding_txout, watched


class TestCapabilities(ElectrumTestCase):
    async def test_http_capability_and_missing_field_legacy_fallback(self):
        response = {
            "htlcFirst": True,
            "protocols": [TAPROOT_SWAP_PROTOCOL],
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
        self.assertEqual((TAPROOT_SWAP_PROTOCOL,), transport._protocols)
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
            config=SimpleNamespace(
                NOSTR_RELAYS="wss://relay.example", SWAPSERVER_ANN_POW_NONCE=0,
            ),
        )
        response = await HttpSwapServer.get_pairs(SimpleNamespace(sm=sm), None)
        self.assertEqual(
            [TAPROOT_SWAP_PROTOCOL], json.loads(response.body)["protocols"],
        )

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
            [TAPROOT_SWAP_PROTOCOL],
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
        stored_swaps = {}
        manager.wallet = SimpleNamespace(
            db=SimpleNamespace(get_dict=lambda _key: stored_swaps),
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
                protocols=(TAPROOT_SWAP_PROTOCOL,), send_request_to_server=send,
            ),
            lightning_amount_sat=LIGHTNING_AMOUNT,
            expected_onchain_amount_sat=ONCHAIN_AMOUNT,
        )
        self.assertEqual(TAPROOT_SWAP_PROTOCOL, swap.protocol)
        self.assertEqual(PROVIDER_PUBKEY, swap.their_pubkey)
        restored = manager.get_taproot_contract(swap)
        self.assertIs(SwapDirection.FORWARD, restored.direction)
        self.assertEqual(PROVIDER_PUBKEY, restored.provider_pubkey)
        self.assertEqual(swap.redeem_script, restored.output_script)
        self.assertIs(swap, manager._swaps[PAYMENT_HASH.hex()])

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
                            protocols=(TAPROOT_SWAP_PROTOCOL,), send_request_to_server=send,
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
        for tamper in (None, "tree", "missing-prepay", "same-hash", "zero-conf", "extra-field"):
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
                                protocols=(TAPROOT_SWAP_PROTOCOL,), send_request_to_server=send,
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
                    else:
                        with self.assertRaises(SwapServerError):
                            await manager.reverse_swap(
                                transport=SimpleNamespace(
                                    protocols=(TAPROOT_SWAP_PROTOCOL,),
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
        for field in ("protocol", "their_pubkey", "is_provider"):
            legacy.pop(field)
        restored = SwapData(**legacy)
        self.assertIsNone(restored.protocol)
        self.assertIsNone(restored.their_pubkey)
        self.assertFalse(restored.is_provider)

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
                    should_claim, manager.wallet.txbatcher.add_sweep_input.called,
                )
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
