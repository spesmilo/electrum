import importlib.util
import io
import sys
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

try:
    import usb1
    from trezorlib import messages
except ImportError:
    raise unittest.SkipTest("OneKey tests require trezor and libusb1")

from electrum import constants, descriptor
from electrum.bip32 import BIP32Node, convert_bip32_strpath_to_intpath
from electrum.plugin import run_in_hwd_thread
from electrum.plugins.onekey import messages as management
from electrum.plugins.onekey.client import OneKeyClient, coin_name
from electrum.plugins.onekey.onekey import OneKeyKeyStore, OneKeyPlugin
from electrum.plugins.onekey.transport import Transport, crc8, encode_frame
from electrum.transaction import PartialTransaction, PartialTxInput, PartialTxOutput, Transaction, TxOutpoint, Sighash
from electrum.util import UserCancelled, UserFacingException
from electrum.zip_importer import MemoryZipImporter


SUPPORTED_MESSAGES = [60200, 60600, 60602, 61200, 61202, 61203]


def device_status(**kwargs):
    fields = dict(device_id="test-device", init_states=True, unlocked=True,
                  passphrase_enabled=False, unlocked_by_attach_to_pin=False)
    fields.update(kwargs)
    return management.DeviceStatus(**fields)


def wallet_session(**kwargs):
    fields = dict(session_id=b"test-session", btc_test_address="test-wallet", seed_domains=[1])
    fields.update(kwargs)
    return management.DeviceSession(**fields)


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.closed = False

    def write(self, wire_type, payload):
        self.requests.append(management.MAPPING.decode(wire_type, payload))

    def read(self, **kwargs):
        if kwargs.get("cancelled") and kwargs["cancelled"]():
            raise UserCancelled()
        return management.MAPPING.encode(self.responses.pop(0))

    def close(self):
        self.closed = True


class TestOneKeyTransport(unittest.TestCase):
    def make_transport(self, chunks=()):
        transport = Transport.__new__(Transport)
        transport.context = mock.Mock()
        transport.handle = mock.Mock()
        transport.handle.bulkRead.side_effect = list(chunks)
        transport.interface = 0
        transport.ep_in = 0x81
        transport.ep_out = 1
        transport.sequence = 0
        transport.buffer = bytearray()
        return transport

    def test_firmware_crc_and_protocol_info_vector(self):
        # Golden vector computed with the firmware's CRC lookup table.
        self.assertEqual(0x76, crc8(b"123456789"))
        wire_type, payload = management.MAPPING.encode(
            management.ProtocolInfoRequest(eventless_wallet_session=True))
        self.assertEqual(bytes.fromhex("5a0c008200000128eb08018f"),
                         encode_frame(wire_type, payload, 1))

    def test_fragmented_and_coalesced_frames(self):
        first = encode_frame(60603, b"first", 1)
        second = encode_frame(61201, b"second", 2)
        transport = self.make_transport([first[:2], first[2:7], first[7:] + second])
        self.assertEqual((60603, b"first"), transport.read())
        self.assertEqual((61201, b"second"), transport.read())

    def test_corrupt_frames_are_rejected(self):
        frame = encode_frame(60603, b"status", 1)
        for index in (0, 3, -1):
            with self.subTest(index=index):
                corrupt = bytearray(frame)
                corrupt[index] ^= 1
                with self.assertRaises(UserFacingException):
                    self.make_transport([corrupt]).read()

    def test_ack_does_not_hide_following_response(self):
        ack = bytearray.fromhex("5a08000000010100")
        ack[3] = crc8(ack[:3])
        ack[-1] = crc8(ack[:-1])
        response = encode_frame(60603, b"status", 2)
        self.assertEqual((60603, b"status"), self.make_transport([ack + response]).read())

    def test_cancel_does_not_wait_for_usb(self):
        transport = self.make_transport()
        with self.assertRaises(UserCancelled):
            transport.read(cancelled=lambda: True)
        transport.handle.bulkRead.assert_not_called()

    def test_timeout_and_short_write_are_not_retried(self):
        transport = self.make_transport()
        transport.handle.bulkRead.side_effect = usb1.USBErrorTimeout()
        with mock.patch("electrum.plugins.onekey.transport.time.monotonic", side_effect=[0, 0, 2]):
            with self.assertRaisesRegex(UserFacingException, "timed out"):
                transport.read(timeout=1)
        transport.handle.bulkRead.assert_called_once()
        transport.handle.bulkWrite.return_value = 1
        with self.assertRaisesRegex(UserFacingException, "Incomplete"):
            transport.write(15, b"sign")
        transport.handle.bulkWrite.assert_called_once()


class TestOneKeyPackaging(unittest.TestCase):
    def test_external_zip_loads_dependencies_on_first_import(self):
        root_name = "onekey_zip_test.onekey"
        source = Path(__file__).parent.parent / "electrum/plugins/onekey"
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zipped:
            for name in ("__init__.py", "onekey.py", "client.py", "messages.py", "transport.py"):
                zipped.writestr("onekey/" + name, (source / name).read_bytes())
        importer = MemoryZipImporter(archive.getvalue(), root_name=root_name,
                                     prefix="onekey", archive_path="onekey-test.zip").install()
        try:
            # Electrum loads ZIP packages without a real parent package on disk.
            for module_name in (root_name, root_name + ".onekey"):
                spec = importer.find_spec(module_name)
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
            plugin = module.OneKeyPlugin.__new__(module.OneKeyPlugin)
            self.assertEqual(OneKeyPlugin.__new__(OneKeyPlugin).get_library_version(),
                             plugin.get_library_version())
            self.assertIn(root_name + ".client", sys.modules)
        finally:
            sys.meta_path.remove(importer)
            for name in list(sys.modules):
                if name == root_name or name.startswith(root_name + "."):
                    del sys.modules[name]


class TestOneKeyClient(unittest.TestCase):
    def make_client(self, *, model=7, supported=None):
        transport = FakeTransport([
            management.ProtocolInfo(version=1, build_fingerprint="application__test",
                                    supported_messages=SUPPORTED_MESSAGES if supported is None else supported),
            management.DeviceInfo(protocol_version=1, hw=management.DeviceHardwareInfo(
                device_type=model, serial_no="test-serial")),
            device_status(),
        ])
        self.addCleanup(lambda: transport.close())
        handler = mock.Mock()
        plugin = SimpleNamespace(SUPPORTED_XTYPES=OneKeyPlugin.SUPPORTED_XTYPES)
        with mock.patch("electrum.plugins.onekey.client.Transport", return_value=transport):
            client = run_in_hwd_thread(lambda: OneKeyClient("test", handler, plugin))
        return client, transport, handler

    def test_both_models_and_noninteractive_enumeration(self):
        for model, name in ((7, "OneKey Pro 2"), (8, "OneKey Neo")):
            with self.subTest(model=model):
                client, transport, handler = self.make_client(model=model)
                self.assertEqual(name, client.device_model_name())
                self.assertEqual("test-device", client.get_soft_device_id())
                self.assertTrue(client.is_initialized())
                handler.show_message.assert_not_called()
                self.assertEqual([60200, 60600, 60602],
                                 [request.MESSAGE_WIRE_TYPE for request in transport.requests])

    def test_loaders_and_other_models_are_rejected(self):
        with self.assertRaisesRegex(UserFacingException, "Unsupported OneKey firmware"):
            self.make_client(supported=[60200, 60600])
        with self.assertRaisesRegex(UserFacingException, "Pro 2 and Neo only"):
            self.make_client(model=5)

    def test_bitcoin_handlers_need_not_be_advertised_by_management_registry(self):
        client, transport, handler = self.make_client(supported=SUPPORTED_MESSAGES)
        self.assertEqual("OneKey Pro 2", client.device_model_name())
        self.assertFalse(transport.closed)
        handler.show_message.assert_not_called()

    def test_passphrase_session_and_resume(self):
        client, transport, handler = self.make_client()
        transport.responses.extend([
            device_status(unlocked=False, passphrase_enabled=None, unlocked_by_attach_to_pin=None),
            management.Success(), device_status(passphrase_enabled=True),
            messages.ButtonRequest(), management.Success(), wallet_session(),
            device_status(passphrase_enabled=True), wallet_session(),
        ])
        run_in_hwd_thread(lambda: self._open_twice(client))
        requests = transport.requests[3:]
        self.assertIsInstance(requests[1], management.DeviceSessionAskPin)
        self.assertEqual(1, requests[1].type)
        self.assertIsInstance(requests[3], management.DeviceSessionAskPassphrase)
        self.assertTrue(requests[3].on_device)
        self.assertIsNone(requests[3].passphrase)
        self.assertEqual([1], requests[3].seed_domains)
        self.assertIsInstance(requests[4], messages.ButtonAck)
        self.assertEqual(b"test-session", requests[-1].session_id)
        self.assertEqual("test-wallet", requests[-1].btc_test_address)
        self.assertEqual(2, handler.finished.call_count)

    @staticmethod
    def _open_twice(client):
        with client:
            pass
        with client:
            pass

    def test_session_change_aborts_before_bitcoin_requests(self):
        client, transport, handler = self.make_client()
        client.session = wallet_session()
        transport.responses.extend([device_status(), wallet_session(session_id=b"other-wallet")])
        with self.assertRaisesRegex(UserFacingException, "session changed"):
            client.show_address([0], "p2pkh", "expected")
        self.assertTrue(transport.closed)
        self.assertIsNone(client.session)
        self.assertFalse(any(isinstance(req, messages.GetAddress) for req in transport.requests))
        self.assertIsInstance(transport.requests[-1], messages.Cancel)
        handler.finished.assert_called_once()

    def test_expired_session_does_not_derive_another_wallet(self):
        client, transport, _ = self.make_client()
        client.session = wallet_session()
        transport.responses.extend([device_status(), management.Failure(code=5, subcode=2, message="Invalid session")])
        with self.assertRaisesRegex(UserFacingException, "Invalid session"):
            client.get_xpub("m/84'/0'/0'", "p2wpkh")
        self.assertFalse(any(isinstance(req, management.DeviceSessionAskPassphrase) for req in transport.requests))
        self.assertTrue(transport.closed)

    def test_attach_pin_session_and_mode_change_rejection(self):
        client, transport, handler = self.make_client()
        transport.responses.extend([
            device_status(unlocked=False, passphrase_enabled=None, unlocked_by_attach_to_pin=None),
            management.Success(),
            device_status(passphrase_enabled=True, unlocked_by_attach_to_pin=True),
            wallet_session(),
            device_status(passphrase_enabled=True, unlocked_by_attach_to_pin=True),
            wallet_session(),
        ])
        run_in_hwd_thread(lambda: self._open_twice(client))
        requests = transport.requests[3:]
        self.assertIsInstance(requests[1], management.DeviceSessionAskPin)
        self.assertEqual(1, requests[1].type)
        self.assertFalse(any(isinstance(req, management.DeviceSessionAskPassphrase) for req in requests))
        self.assertTrue(client.session_attach_pin)
        self.assertFalse(transport.closed)
        self.assertEqual(2, handler.finished.call_count)

        # Switching from Attach PIN to Main PIN invalidates the active session.
        transport.responses.append(device_status(unlocked_by_attach_to_pin=False))
        with self.assertRaisesRegex(UserFacingException, "session changed"):
            client.show_address([0], "p2pkh", "expected")
        self.assertTrue(transport.closed)

    def test_address_mismatch_and_device_cancellation(self):
        for response, error, should_close in (
            (messages.Address(address="wrong-address"), UserFacingException, True),
            (management.Failure(code=5, subcode=1, message="Cancelled"), UserCancelled, False),
        ):
            with self.subTest(response=type(response).__name__):
                client, transport, _ = self.make_client()
                client.session = wallet_session()
                transport.responses.extend([device_status(), wallet_session(), response])
                with self.assertRaises(error):
                    client.show_address([0], "p2wpkh", "expected-address")
                self.assertEqual(should_close, transport.closed)

    def test_xpub_header_conversion_and_standard_session(self):
        client, transport, _ = self.make_client()
        root = BIP32Node.from_rootseed(b"onekey-test", xtype="standard")
        transport.responses.extend([
            device_status(), wallet_session(),
            messages.PublicKey(xpub=root.to_xpub(), node=messages.HDNodeType(
                depth=0, fingerprint=0, child_num=0, chain_code=root.chaincode,
                public_key=root.eckey.get_public_key_bytes(compressed=True))),
        ])
        xpub = client.get_xpub("m/84'/0'/0'", "p2wpkh")
        self.assertEqual("p2wpkh", BIP32Node.from_xkey(xpub).xtype)
        self.assertFalse(any(isinstance(req, management.DeviceSessionAskPassphrase) for req in transport.requests))
        self.assertFalse(transport.closed)

    def test_testnet_coin_name(self):
        with mock.patch.object(constants, "net", constants.BitcoinTestnet):
            self.assertEqual("Testnet", coin_name())


class TestOneKeySigning(unittest.TestCase):
    def make_transaction(self, script_type="p2wpkh"):
        root = BIP32Node.from_rootseed(b"onekey signing regression", xtype="standard")
        prefix = "m/84'/0'/0'"
        account = root.subkey_at_private_derivation(prefix)
        fingerprint = root.calc_fingerprint_of_this_node()
        keystore = OneKeyKeyStore(dict(xpub=account.to_xpub(), derivation=prefix,
                                      root_fingerprint=fingerprint.hex()))

        def make_output(index, value):
            node = account.subkey_at_private_derivation([0, index])
            pubkey = node.eckey.get_public_key_bytes(compressed=True)
            desc = descriptor.get_singlesig_descriptor_from_legacy_leaf(pubkey=pubkey.hex(), script_type=script_type)
            output = PartialTxOutput(scriptpubkey=desc.expand().output_script, value=value)
            output.script_descriptor = desc
            output.bip32_paths[pubkey] = (fingerprint, convert_bip32_strpath_to_intpath(prefix) + [0, index])
            return output, node

        funding_output, input_node = make_output(0, 100000)
        raw = (bytes.fromhex("0200000001") + bytes(32) + bytes.fromhex("ffffffff0100ffffffff01")
               + (100000).to_bytes(8, "little") + bytes([len(funding_output.scriptpubkey)])
               + funding_output.scriptpubkey + bytes(4))
        funding = Transaction(raw.hex())
        txin = PartialTxInput(prevout=TxOutpoint(txid=bytes.fromhex(funding.txid()), out_idx=0))
        txin.utxo = funding
        txin.script_descriptor = funding_output.script_descriptor
        txin.bip32_paths = funding_output.bip32_paths
        txin.is_mine = True
        recipient, _ = make_output(1, 60000)
        change, _ = make_output(2, 39000)
        change.is_mine = change.is_change = True
        tx = PartialTransaction.from_io(inputs=[txin], outputs=[recipient, change],
                                        version=2, locktime=123, BIP69_sort=False)
        return keystore, tx, input_node

    def test_signing_all_supported_script_types(self):
        for script_type in ("p2pkh", "p2wpkh-p2sh", "p2wpkh"):
            with self.subTest(script_type=script_type):
                keystore, tx, node = self.make_transaction(script_type)
                signature = tx.sign_txin(0, node.eckey.get_secret_bytes())[:-1]
                client = mock.Mock()
                client.sign_tx.return_value = [signature]
                plugin = OneKeyPlugin.__new__(OneKeyPlugin)
                plugin.get_client = mock.Mock(return_value=client)
                plugin.sign_transaction(keystore, tx)
                self.assertTrue(tx.is_complete())
                inputs, outputs, previous = client.sign_tx.call_args.args
                self.assertEqual(100000, inputs[0].amount)
                self.assertEqual(60000, outputs[0].amount)
                self.assertIsNotNone(outputs[0].address)
                self.assertEqual(39000, outputs[1].amount)
                self.assertTrue(outputs[1].address_n)
                self.assertEqual(100000, previous[inputs[0].prev_hash].bin_outputs[0].amount)
                self.assertEqual(dict(version=2, lock_time=123), client.sign_tx.call_args.kwargs)

    def test_foreign_input_and_nondefault_sighash_are_rejected(self):
        for foreign, sighash in ((True, None), (False, Sighash.NONE)):
            with self.subTest(foreign=foreign, sighash=sighash):
                keystore, tx, _ = self.make_transaction()
                tx.inputs()[0].is_mine = not foreign
                tx.inputs()[0].sighash = sighash
                plugin = OneKeyPlugin.__new__(OneKeyPlugin)
                plugin.get_client = mock.Mock()
                with self.assertRaises(UserFacingException):
                    plugin.sign_transaction(keystore, tx)
                plugin.get_client.assert_not_called()

    def test_signing_wire_request_loop(self):
        case = TestOneKeyClient()
        self.addCleanup(case.doCleanups)
        client, transport, _ = case.make_client()
        client.session = wallet_session()
        transport.responses.extend([
            device_status(), wallet_session(),
            messages.TxRequest(request_type=messages.RequestType.TXINPUT,
                               details=messages.TxRequestDetailsType(request_index=0)),
            messages.TxRequest(request_type=messages.RequestType.TXOUTPUT,
                               details=messages.TxRequestDetailsType(request_index=0)),
            messages.TxRequest(request_type=messages.RequestType.TXFINISHED,
                               serialized=messages.TxRequestSerializedType(signature_index=0, signature=b"signature")),
        ])
        inputs = [messages.TxInputType(prev_hash=bytes(32), prev_index=0, address_n=[0], amount=100000)]
        outputs = [messages.TxOutputType(amount=99000, address="recipient", script_type=messages.OutputScriptType.PAYTOADDRESS)]
        signatures = client.sign_tx(inputs, outputs, {}, version=2, lock_time=123)
        self.assertEqual([b"signature"], signatures)
        request = next(req for req in transport.requests if isinstance(req, messages.SignTx))
        self.assertFalse(request.serialize)
        self.assertEqual(123, request.lock_time)
        acks = [req for req in transport.requests if isinstance(req, messages.TxAck)]
        self.assertEqual(inputs, acks[0].tx.inputs)
        self.assertEqual(outputs, acks[1].tx.outputs)
