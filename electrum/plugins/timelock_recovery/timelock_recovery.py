from datetime import datetime
from typing import TYPE_CHECKING, Callable, List, Optional, Sequence, Tuple
from electrum.bitcoin import address_to_script
from electrum.plugin import BasePlugin
from electrum.transaction import PartialTxOutput, PartialTxInput, TxOutpoint
from electrum.util import bfh

if TYPE_CHECKING:
    from electrum.gui.qt import ElectrumWindow
    from electrum.transaction import PartialTransaction, TxOutput
    from electrum.wallet import Abstract_Wallet

ALERT_ADDRESS_LABEL = "Timelock Recovery Alert Address"
CANCELLATION_ADDRESS_LABEL = "Timelock Recovery Cancellation Address"

class PartialTxInputWithFixedNsequence(PartialTxInput):
    _fixed_nsequence: int

    def __init__(self, *args, nsequence: int = 0xfffffffe, **kwargs):
        self._fixed_nsequence = nsequence
        super().__init__(*args, **kwargs)

    @property
    def nsequence(self) -> int:
        return self._fixed_nsequence

    @nsequence.setter
    def nsequence(self, value: int):
        pass # ignore override attempts

class TimelockRecoveryContext:
    wallet: 'Abstract_Wallet'
    wallet_name: str
    main_window: Optional['ElectrumWindow'] = None
    timelock_days: Optional[int] = None
    cancellation_address: Optional[str] = None
    outputs: Optional[List['PartialTxOutput']] = None
    alert_tx: Optional['PartialTransaction'] = None
    recovery_tx: Optional['PartialTransaction'] = None
    cancellation_tx: Optional['PartialTransaction'] = None
    recovery_plan_id: Optional[str] = None
    recovery_plan_created_at: Optional[datetime] = None
    _alert_address: Optional[str] = None
    _cancellation_address: Optional[str] = None
    recovery_plan_saved: bool = False
    cancellation_plan_saved: bool = False

    ANCHOR_OUTPUT_AMOUNT_SATS = 600

    def __init__(self, wallet: 'Abstract_Wallet'):
        self.wallet = wallet
        self.wallet_name = str(self.wallet)

    def _get_address_by_label(self, label: str) -> str:
        unused_addresses = list(self.wallet.get_unused_addresses())
        for addr in unused_addresses:
            if self.wallet.get_label_for_address(addr) == label:
                return addr
        for addr in unused_addresses:
            if not self.wallet.is_address_reserved(addr) and not self.wallet.get_label_for_address(addr):
                self.wallet.set_label(addr, label)
                return addr
        if self.wallet.is_deterministic():
            addr = self.wallet.create_new_address(False)
            if addr:
                self.wallet.set_label(addr, label)
                return addr
        return ''

    def get_alert_address(self) -> str:
        if self._alert_address is None:
            self._alert_address = self._get_address_by_label(ALERT_ADDRESS_LABEL)
        return self._alert_address

    def get_cancellation_address(self) -> str:
        if self._cancellation_address is None:
            self._cancellation_address = self._get_address_by_label(CANCELLATION_ADDRESS_LABEL)
        return self._cancellation_address

    def make_unsigned_alert_tx(self, fee_policy) -> 'PartialTransaction':
        alert_tx_outputs = [
            PartialTxOutput(scriptpubkey=address_to_script(self.get_alert_address()), value='!'),
        ] + [
            PartialTxOutput(scriptpubkey=output.scriptpubkey, value=self.ANCHOR_OUTPUT_AMOUNT_SATS)
            for output in self.outputs
        ]
        return self.wallet.make_unsigned_transaction(
            coins=self.wallet.get_spendable_coins(confirmed_only=False),
            outputs=alert_tx_outputs,
            fee_policy=fee_policy,
            is_sweep=False,
            locktime=self.alert_tx.locktime if self.alert_tx else None,
        )

    def _alert_tx_output(self) -> Tuple[int, 'TxOutput']:
        tx_outputs: List[Tuple[int, 'TxOutput']] = [
            (index, tx_output) for index, tx_output in enumerate(self.alert_tx.outputs())
            if tx_output.address == self.get_alert_address() and tx_output.value != self.ANCHOR_OUTPUT_AMOUNT_SATS
        ]
        if len(tx_outputs) != 1:
            # Safety check - not expected to happen
            raise ValueError(f"Expected 1 output from the Alert transaction to the Alert Address, but got {len(tx_outputs)}.")
        return tx_outputs[0]

    def _alert_tx_outpoint(self, out_idx: int) -> TxOutpoint:
        return TxOutpoint(txid=bfh(self.alert_tx.txid()), out_idx=out_idx)

    def make_unsigned_recovery_tx(self, fee_policy) -> 'PartialTransaction':
        prevout_index, prevout = self._alert_tx_output()
        nsequence: int = round(self.timelock_days * 24 * 60 * 60 / 512)
        if nsequence > 0xFFFF:
            # Safety check - not expected to happen
            raise ValueError("Sequence number is too large")
        nsequence += 0x00400000 # time based lock instead of block-height based lock
        recovery_tx_input = PartialTxInputWithFixedNsequence(
            prevout=self._alert_tx_outpoint(prevout_index),
            nsequence=nsequence,
        )
        recovery_tx_input.witness_utxo = prevout

        return self.wallet.make_unsigned_transaction(
            coins=[recovery_tx_input],
            outputs=[output for output in self.outputs if output.value != 0],
            fee_policy=fee_policy,
            is_sweep=False,
            locktime=self.recovery_tx.locktime if self.recovery_tx else None,
        )

    def add_input_info_to_recovery_tx(self):
        if self.recovery_tx and self.alert_tx.is_complete():
            self.recovery_tx.inputs()[0].utxo = self.alert_tx

    def add_input_info_to_cancellation_tx(self):
        if self.cancellation_tx and self.alert_tx.is_complete():
            self.cancellation_tx.inputs()[0].utxo = self.alert_tx

    def make_unsigned_cancellation_tx(self, fee_policy) -> 'PartialTransaction':
        prevout_index, prevout = self._alert_tx_output()
        cancellation_tx_input = PartialTxInput(
            prevout=self._alert_tx_outpoint(prevout_index),
        )
        cancellation_tx_input.witness_utxo = prevout

        return self.wallet.make_unsigned_transaction(
            coins=[cancellation_tx_input],
            outputs=[
                PartialTxOutput(scriptpubkey=address_to_script(self.get_cancellation_address()), value='!'),
            ],
            fee_policy=fee_policy,
            is_sweep=False,
            locktime=self.cancellation_tx.locktime if self.cancellation_tx else None,
        )

class TimelockRecoveryPlugin(BasePlugin):
    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
