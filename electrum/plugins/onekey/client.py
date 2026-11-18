import sys
import threading
from contextlib import suppress
from importlib.metadata import version

from trezorlib import btc, messages

from electrum import constants
from electrum.bip32 import BIP32Node, convert_bip32_strpath_to_intpath
from electrum.hw_wallet import HardwareClientBase
from electrum.i18n import _
from electrum.plugin import runs_in_hwd_thread
from electrum.util import UserCancelled, UserFacingException

from .messages import (
    MAPPING, ProtocolInfoRequest, ProtocolInfo, Success, Failure,
    DeviceInfoTargets, DeviceInfoTypes, DeviceInfoGet, DeviceInfo,
    DeviceStatusGet, DeviceStatus, DeviceSessionGet, DeviceSession,
    DeviceSessionAskPin, DeviceSessionAskPassphrase,
)
from .transport import Transport


LIBRARY_VERSION = version("trezor")
MODELS = {7: "OneKey Pro 2", 8: "OneKey Neo"}
INPUT_SCRIPT_TYPES = {
    "standard": messages.InputScriptType.SPENDADDRESS,
    "p2pkh": messages.InputScriptType.SPENDADDRESS,
    "p2wpkh-p2sh": messages.InputScriptType.SPENDP2SHWITNESS,
    "p2wpkh": messages.InputScriptType.SPENDWITNESS,
}
OUTPUT_SCRIPT_TYPES = {
    "p2pkh": messages.OutputScriptType.PAYTOADDRESS,
    "p2wpkh-p2sh": messages.OutputScriptType.PAYTOP2SHWITNESS,
    "p2wpkh": messages.OutputScriptType.PAYTOWITNESS,
}


def coin_name():
    return "Testnet" if constants.net.TESTNET else "Bitcoin"


class OneKeyClient(HardwareClientBase):
    def __init__(self, path, handler, plugin):
        super().__init__(plugin=plugin)
        self.handler = handler
        self.transport = Transport(path)
        self.cancelled = threading.Event()
        self.flow_depth = 0
        self.session = None
        try:
            protocol = self.call(
                ProtocolInfoRequest(eventless_wallet_session=True),
                expect=ProtocolInfo,
            )
            required = {
                message.MESSAGE_WIRE_TYPE for message in (
                    DeviceInfoGet, DeviceStatusGet,
                    DeviceSessionGet, DeviceSessionAskPin,
                    DeviceSessionAskPassphrase, messages.GetPublicKey,
                    messages.GetAddress, messages.SignTx,
                )
            }
            # Protocol V2's management schema currently reports version 1.
            if protocol.version != 1 or not required.issubset(protocol.supported_messages):
                raise UserFacingException(_("Unsupported OneKey firmware. Update the device firmware."))
            info = self.call(DeviceInfoGet(
                targets=DeviceInfoTargets(hw=True),
                types=DeviceInfoTypes(specific=True),
            ), expect=DeviceInfo)
            if info.protocol_version != 1 or info.hw is None or info.hw.device_type not in MODELS:
                raise UserFacingException(_("This plugin supports OneKey Pro 2 and Neo only."))
            self.model = MODELS[info.hw.device_type]
            self.serial = info.hw.serial_no
            self.status = self.call(DeviceStatusGet(), expect=DeviceStatus)
            if not self.status.device_id or self.status.init_states is None:
                raise UserFacingException(_("Incomplete OneKey device status."))
            self.device_id = self.status.device_id
        except BaseException:
            self.close()
            raise

    def call(self, request, *, expect):
        wire_type, payload = MAPPING.encode(request)
        self.transport.write(wire_type, payload)
        while True:
            wire_type, payload = self.transport.read(
                cancelled=self.cancelled.is_set if self.flow_depth else None,
                timeout=120 if self.flow_depth else 5,
            )
            try:
                response = MAPPING.decode(wire_type, payload)
            except (KeyError, ValueError, EOFError) as e:
                raise UserFacingException(_("Invalid OneKey response.")) from e
            if isinstance(response, Failure):
                if response.code == 5 and response.subcode == 1:
                    raise UserCancelled()
                raise UserFacingException(
                    response.message or _("OneKey request failed.")
                )
            if isinstance(response, messages.ButtonRequest):
                if not self.flow_depth:
                    raise UserFacingException(_("Unexpected OneKey confirmation request."))
                self.transport.write(*MAPPING.encode(messages.ButtonAck()))
                continue
            if not isinstance(response, expect):
                raise UserFacingException(_("Unexpected OneKey response."))
            return response

    def _ensure_session(self):
        status = self.call(DeviceStatusGet(), expect=DeviceStatus)
        if status.device_id != self.device_id or not status.init_states:
            raise UserFacingException(_("OneKey device identity or initialization changed. Reconnect the device."))
        if self.session is not None:
            if status.unlocked is not True:
                raise UserFacingException(_("OneKey was locked. Reconnect and unlock the device."))
            session = self.call(DeviceSessionGet(
                session_id=self.session.session_id,
                btc_test_address=self.session.btc_test_address,
            ), expect=DeviceSession)
            if (session.session_id != self.session.session_id
                    or session.btc_test_address != self.session.btc_test_address
                    or 1 not in session.seed_domains):
                raise UserFacingException(_("OneKey wallet session changed. Reconnect the device."))
            return

        if status.unlocked is not True or status.unlocked_by_attach_to_pin is not False:
            self.call(DeviceSessionAskPin(type=2), expect=Success)
            status = self.call(DeviceStatusGet(), expect=DeviceStatus)
        if (status.device_id != self.device_id or status.unlocked is not True
                or status.unlocked_by_attach_to_pin is not False
                or status.passphrase_enabled is None):
            raise UserFacingException(_("Unlock OneKey with the main PIN to continue."))

        if status.passphrase_enabled:
            self.handler.show_message(_(
                "Enter the passphrase on your OneKey. Leave it empty for the standard wallet."
            ), on_cancel=self.cancelled.set)
            self.call(DeviceSessionAskPassphrase(
                on_device=True, seed_domains=[1],
            ), expect=Success)
        session = self.call(DeviceSessionGet(), expect=DeviceSession)
        if not session.session_id or not session.btc_test_address or 1 not in session.seed_domains:
            raise UserFacingException(_("Incomplete OneKey wallet session."))
        self.session = session

    def __enter__(self):
        if self.flow_depth:
            self.flow_depth += 1
            return self
        if self.handler is None or self.transport is None:
            raise UserFacingException(_("Reconnect your OneKey using the wallet wizard."))
        self.cancelled.clear()
        self.flow_depth = 1
        self.handler.show_message(_("Check your OneKey device to continue."), on_cancel=self.cancelled.set)
        try:
            self._ensure_session()
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.flow_depth -= 1
        if self.flow_depth:
            return
        try:
            if exc_type is not None:
                # Abort, without replaying an address or signing request after a timeout.
                with suppress(Exception):
                    self.transport.write(*MAPPING.encode(messages.Cancel()))
                self.close()
        finally:
            self.handler.finished()

    @runs_in_hwd_thread
    def close(self):
        self.session = None
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    def is_pairable(self):
        return True

    def is_initialized(self):
        return bool(self.status.init_states)

    def label(self):
        return f"{self.model} ({self.serial or self.device_id})"

    def device_model_name(self):
        return self.model

    def get_soft_device_id(self):
        return self.device_id

    @runs_in_hwd_thread
    def has_usable_connection_with_device(self):
        if self.transport is None:
            return False
        try:
            status = self.call(DeviceStatusGet(), expect=DeviceStatus)
            return status.device_id == self.device_id
        except Exception:
            return False

    @runs_in_hwd_thread
    def get_xpub(self, bip32_path, xtype):
        if xtype not in self.plugin.SUPPORTED_XTYPES:
            raise UserFacingException(_("Unsupported OneKey script type."))
        with self:
            response = self.call(messages.GetPublicKey(
                address_n=convert_bip32_strpath_to_intpath(bip32_path),
                coin_name=coin_name(), script_type=INPUT_SCRIPT_TYPES[xtype],
            ), expect=messages.PublicKey)
            return BIP32Node.from_xkey(response.xpub)._replace(xtype=xtype).to_xpub()

    @runs_in_hwd_thread
    def show_address(self, path, script_type, expected_address):
        with self:
            response = self.call(messages.GetAddress(
                address_n=path, coin_name=coin_name(), show_display=True,
                script_type=INPUT_SCRIPT_TYPES[script_type],
            ), expect=messages.Address)
            if response.address != expected_address:
                raise UserFacingException(_("OneKey returned a different address. Check the selected wallet."))

    @runs_in_hwd_thread
    def sign_tx(self, inputs, outputs, prev_txes, *, version, lock_time):
        with self:
            signatures, _ = btc.sign_tx(
                self, coin_name(), inputs, outputs, prev_txes=prev_txes,
                version=version, lock_time=lock_time, serialize=False,
            )
            return signatures
