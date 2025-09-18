import re
import json
import time
import datetime
import threading
import requests
import os
from typing import Dict, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QLineEdit, QMessageBox, QFrame, QHBoxLayout, QTextEdit
from PyQt6.QtGui import QAction
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QObject, QEvent

from electrum.plugin import BasePlugin, hook
from electrum.wallet import Abstract_Wallet
from electrum.transaction import Transaction
from electrum.gui.qt.main_window import ElectrumWindow
from electrum.bitcoin import address_to_scripthash

# Signal parsing constants
MAX_SIGNAL_LEN = 40
NONCE_MAX = 2**32 - 1
SIGNAL_REGEX = re.compile(r'^guardv1\.Lock=(true|false)#[0-9]+$')

def parse_signal(payload: str) -> Optional[Dict]:
    if len(payload) > MAX_SIGNAL_LEN:
        return None
    if not SIGNAL_REGEX.match(payload):
        return None
    try:
        prefix, rest = payload.split('.', 1)
        key, remainder = rest.split('=', 1)
        val, nonce_str = remainder.split('#', 1)
        if prefix != "guardv1" or key != "Lock":
            return None
        if val not in ("true", "false"):
            return None
        if len(nonce_str) > 1 and nonce_str[0] == "0":
            return None
        nonce = int(nonce_str)
        if not (0 <= nonce <= NONCE_MAX):
            return None
        return {
            "locked": (val == "true"),
            "nonce": nonce,
            "payload": payload,
        }
    except Exception:
        return None

def extract_signal_from_tx(tx: Transaction):
    try:
        for o in tx.outputs():
            script = o.scriptpubkey
            if not script or script[0] != 0x6a:  # OP_RETURN
                continue
            data = script[1:]
            if not data:
                continue
            push_len = data[0]
            if len(data) < push_len + 1:
                continue
            payload = data[1:1 + push_len]
            try:
                payload_str = payload.decode('ascii')
            except Exception:
                continue
            sig = parse_signal(payload_str)
            if sig:
                sig["txid"] = tx.txid()
                return sig
    except Exception:
        pass
    return None

class GuardianState:
    def __init__(self, address: str, locked: bool = False, nonce: int = 0, disabled: bool = False):
        self.address = address
        self.locked = locked
        self.nonce = nonce
        self.history = []
        self.processed_txids = set()  # Track processed transaction IDs
        self.disabled = disabled  # New field to disable Guardian functionality

    def is_active(self):
        """Check if Guardian is active (configured and not disabled)"""
        return not self.disabled

    def apply_signal(self, sig: Dict) -> bool:
        """Apply a guardian signal and return True if lock state changed"""
        nonce = sig["nonce"]
        txid = sig["txid"]

        # Don't process the same transaction twice
        if txid in self.processed_txids:
            return False

        # Only apply signals with higher nonces (BIP compliance)
        if nonce <= self.nonce:
            # Still mark as processed to avoid reprocessing
            self.processed_txids.add(txid)
            return False

        # Apply the signal
        old_locked = self.locked
        old_nonce = self.nonce

        self.nonce = nonce
        self.locked = sig["locked"]
        self.processed_txids.add(txid)

        # Add to history
        self.history.append({
            "txid": txid,
            "nonce": nonce,
            "locked": self.locked,
            "observed_time": int(time.time()),
            "payload": sig.get("payload", ""),
        })

        print(f"[Guardian] Applied signal: nonce {old_nonce}->{nonce}, locked {old_locked}->{self.locked}")

        # Return True only if lock state actually changed
        return old_locked != self.locked

    def serialize(self):
        return {
            "address": self.address,
            "locked": self.locked,
            "nonce": self.nonce,
            "history": self.history,
            "processed_txids": list(self.processed_txids),
            "disabled": self.disabled
        }

    @classmethod
    def from_config(cls, d: dict):
        obj = cls(d["address"], d.get("locked", False), d.get("nonce", 0), d.get("disabled", False))
        obj.history = d.get("history", [])
        obj.processed_txids = set(d.get("processed_txids", []))
        return obj

class GuardianTabClickFilter(QObject):
    """Event filter to prevent clicking on Send tab when Guardian is locked"""

    def __init__(self, guardian_plugin):
        super().__init__()
        self.guardian_plugin = guardian_plugin

    def eventFilter(self, source, event):
        # Only handle mouse press events on tab bar
        if event.type() == QEvent.Type.MouseButtonPress:
            try:
                # Get which tab was clicked
                tab_bar = source
                clicked_index = tab_bar.tabAt(event.position().toPoint())

                # Check if it's the Send tab and Guardian is locked
                if clicked_index >= 0:
                    tab_text = self.guardian_plugin.main_window.tabs.tabText(clicked_index).lower()
                    if 'send' in tab_text:
                        if (self.guardian_plugin.guardian_state and
                            self.guardian_plugin.guardian_state.locked):

                            # Show informative message instead of allowing tab switch
                            QMessageBox.warning(
                                self.guardian_plugin.main_window,
                                "Guardian Locked",
                                f"Transactions are prohibited while Guardian is locked.\n\n"
                                f"Guardian Address: {self.guardian_plugin.guardian_state.address}\n"
                                f"Current Nonce: {self.guardian_plugin.guardian_state.nonce}\n\n"
                                f"An unlock signal must be received before the Send tab can be accessed."
                            )

                            # Prevent the tab click by consuming the event
                            return True

            except Exception as e:
                print(f"[Guardian] Error in tab click filter: {e}")

        # Let other events pass through normally
        return super().eventFilter(source, event)

class GuardianPollingThread(QThread):
    """Background thread for Guardian Address polling to avoid blocking UI"""

    signals_updated = pyqtSignal(list)  # Emits list of new signals
    polling_error = pyqtSignal(str)     # Emits error message

    def __init__(self, address):
        super().__init__()
        self.address = address
        self.running = True
        self.processed_txids = set()

    def stop(self):
        self.running = False
        self.quit()
        self.wait()

    def update_processed_txids(self, txids):
        """Update the set of processed transaction IDs"""
        self.processed_txids = set(txids)

    def run(self):
        """Main polling loop - runs in background thread"""
        while self.running:
            try:
                new_signals = self._fetch_signals()
                if new_signals:
                    self.signals_updated.emit(new_signals)
            except Exception as e:
                self.polling_error.emit(str(e))

            # Sleep for 30 seconds, but check every second if we should stop
            for _ in range(30):
                if not self.running:
                    break
                self.msleep(1000)

    def _fetch_signals(self):
        """Fetch and process guardian signals - runs in background"""
        try:
            # Get transaction list
            url = f"https://mempool.space/testnet/api/address/{self.address}/txs"
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                return []

            txs = response.json()

            # Filter out already processed transactions
            new_txs = [tx for tx in txs if tx['txid'] not in self.processed_txids]
            if not new_txs:
                return []

            # Process transactions in parallel for better performance
            signals = []
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_tx = {
                    executor.submit(self._process_transaction, tx): tx
                    for tx in new_txs[:10]  # Limit to 10 most recent
                }

                for future in as_completed(future_to_tx, timeout=15):
                    try:
                        signal = future.result()
                        if signal:
                            signals.append(signal)
                    except Exception as e:
                        print(f"[Guardian] Error processing transaction: {e}")

            return signals

        except Exception as e:
            print(f"[Guardian] Error fetching signals: {e}")
            return []

    def _process_transaction(self, tx):
        """Process a single transaction for guardian signals"""
        try:
            tx_hash = tx['txid']

            # Get transaction hex
            url = f"https://mempool.space/testnet/api/tx/{tx_hash}/hex"
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                return None

            raw_tx = response.text.strip()
            transaction = Transaction(raw_tx)

            signal = extract_signal_from_tx(transaction)
            if signal:
                status = tx.get('status', {})
                signal['height'] = status.get('block_height', 0) if status.get('confirmed', False) else 0
                signal['is_mempool'] = (signal['height'] == 0)
                return signal

        except Exception as e:
            print(f"[Guardian] Error processing transaction {tx.get('txid', 'unknown')}: {e}")

        return None

class Plugin(BasePlugin):
    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)
        self.guardian_state: Optional[GuardianState] = None
        self._network = None
        self.main_window: Optional[ElectrumWindow] = None
        self.status_widget: Optional[QLabel] = None
        self._wallet = None
        self._startup_sync_complete = False
        self._menu_added = False  # Track if menu was added
        print(f"[Guardian] Plugin initialized - parent: {parent}, config: {config}")
        print(f"[Guardian] Plugin name: {name}")

    def _delayed_menu_setup_1(self):
        print("[Guardian] Delayed menu setup attempt 1...")
        if not self._menu_added:
            self._add_guardian_menu()

    def _delayed_menu_setup_2(self):
        print("[Guardian] Delayed menu setup attempt 2...")
        if not self._menu_added:
            self._add_guardian_menu()

    def _delayed_menu_setup_3(self):
        print("[Guardian] Final delayed menu setup attempt 3...")
        if not self._menu_added:
            self._add_guardian_menu()

    def can_user_disable(self):
        """Override to prevent disabling plugin when Guardian is locked"""
        if self.guardian_state and self.guardian_state.locked:
            return False
        return True

    def close(self):
        """Clean shutdown of background threads - but prevent if Guardian locked"""
        if self.guardian_state and self.guardian_state.locked:
            print("[Guardian] Cannot close plugin while Guardian is locked")
            if self.main_window:
                QMessageBox.critical(self.main_window, "Plugin Lock",
                    "Cannot disable Guardian plugin while Guardian is locked.\n\n"
                    "Guardian must be unlocked before the plugin can be disabled.")
            return False  # Prevent closing

        if hasattr(self, '_polling_thread') and self._polling_thread.isRunning():
            print("[Guardian] Stopping background polling thread")
            self._polling_thread.stop()

        if hasattr(self, '_tab_click_filter'):
            self._stop_tab_click_prevention()

        return True

    def register_hooks(self):
        """Manually register hooks - alternative approach"""
        try:
            if hasattr(self, 'parent') and hasattr(self.parent, 'hook_names'):
                print(f"[Guardian] Available hooks: {self.parent.hook_names}")

            # Try manual registration
            if hasattr(self, 'parent'):
                self.parent.register('send_tx', self.hook_send_tx)
                self.parent.register('create_tx', self.hook_create_tx)
                print("[Guardian] Manually registered hooks")
        except Exception as e:
            print(f"[Guardian] Manual hook registration failed: {e}")

    def hook_send_tx(self, wallet: Abstract_Wallet, tx: Transaction):
        """Manual hook function for send_tx"""
        if self.guardian_state and self.guardian_state.locked:
            raise Exception("SECURITY: Transaction blocked by Guardian - wallet is locked")

    def hook_create_tx(self, wallet: Abstract_Wallet, outputs, fee, change_addr, domain, unsigned, rbf, password, locktime, sign):
        """Manual hook function for create_tx"""
        if self.guardian_state and self.guardian_state.locked:
            raise Exception("SECURITY: Transaction creation blocked by Guardian - wallet is locked")

    @hook
    def load_wallet(self, wallet: Abstract_Wallet, main_window: ElectrumWindow):
        print(f"[Guardian] *** LOAD_WALLET HOOK CALLED ***")
        print(f"[Guardian] wallet: {wallet}")
        print(f"[Guardian] main_window: {main_window}")
        print(f"[Guardian] main_window type: {type(main_window)}")

        self.main_window = main_window
        self._network = wallet.network
        self._wallet = wallet

        # Try to add menu immediately
        print("[Guardian] Attempting immediate menu addition...")
        menu_success = self._add_guardian_menu()

        if not menu_success:
            print("[Guardian] Immediate menu addition failed, scheduling delayed attempts...")
            # Schedule multiple attempts with increasing delays
            QTimer.singleShot(1000, self._delayed_menu_setup_1)
            QTimer.singleShot(3000, self._delayed_menu_setup_2)
            QTimer.singleShot(5000, self._delayed_menu_setup_3)

        # Load Guardian configuration
        self._load_guardian_from_storage()

        # Try to register hooks manually as backup
        try:
            self.register_hooks()
        except Exception as e:
            print(f"[Guardian] Error registering hooks: {e}")

        print("[Guardian] load_wallet completed")

    def _load_guardian_from_storage(self):
        """Load Guardian configuration from storage"""
        try:
            print("[Guardian] Loading Guardian configuration from storage...")

            # Try loading from separate config file first (preferred method)
            config_data = self._load_guardian_config()
            if config_data:
                print("[Guardian] Found Guardian in separate config file")
                guardian_addr = config_data.get('address')
                guardian_state_data = config_data.get('state')
                disabled = config_data.get('disabled', False)

                if guardian_addr and not disabled:
                    if guardian_state_data:
                        self.guardian_state = GuardianState.from_config(guardian_state_data)
                    else:
                        self.guardian_state = GuardianState(guardian_addr)

                    print(f"[Guardian] Loaded ACTIVE guardian address from config: {guardian_addr}")
                    print(f"[Guardian] State: locked={self.guardian_state.locked}, nonce={self.guardian_state.nonce}")

                    # Force immediate sync and start polling
                    self._force_immediate_sync()
                    self.start_polling()
                elif disabled:
                    print(f"[Guardian] Guardian found but DISABLED in config file")
                else:
                    print(f"[Guardian] Invalid Guardian config data")
            else:
                print("[Guardian] No Guardian configuration found in config file")

        except Exception as e:
            print(f"[Guardian] Error loading Guardian config: {e}")
            import traceback
            traceback.print_exc()

        # Update status widget and apply protections
        try:
            self._update_status_widget()
            if self.guardian_state and self.guardian_state.locked:
                print("[Guardian] Loaded Guardian in locked state - applying protections")
                self._start_tab_click_prevention()
                self._patch_wallet_methods()
        except Exception as e:
            print(f"[Guardian] Error updating UI or applying protections: {e}")

    def _get_guardian_config_path(self):
        """Get path to separate Guardian configuration file"""
        wallet_path = self._wallet.storage.path
        return wallet_path + ".guardian_config"

    def _load_guardian_config(self):
        """Load Guardian configuration from separate file"""
        try:
            config_path = self._get_guardian_config_path()
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    config_data = json.loads(f.read())
                    print(f"[Guardian] Loaded Guardian config from {config_path}")
                    return config_data
            else:
                print(f"[Guardian] No Guardian config file found at {config_path}")
                return None
        except Exception as e:
            print(f"[Guardian] Error loading Guardian config: {e}")
            return None

    def _save_guardian_config(self, config_data):
        """Save Guardian configuration to separate file"""
        try:
            config_path = self._get_guardian_config_path()
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(json.dumps(config_data, indent=2))
                f.flush()
                os.fsync(f.fileno())
            print(f"[Guardian] Saved Guardian config to {config_path}")
            return True
        except Exception as e:
            print(f"[Guardian] Error saving Guardian config: {e}")
            return False

    def _remove_guardian_config(self):
        """Remove Guardian configuration file"""
        try:
            config_path = self._get_guardian_config_path()
            if os.path.exists(config_path):
                os.remove(config_path)
                print(f"[Guardian] Removed Guardian config file {config_path}")
                return True
            return True  # File doesn't exist, so removal is successful
        except Exception as e:
            print(f"[Guardian] Error removing Guardian config: {e}")
            return False

    def start_polling(self):
        """Start non-blocking polling using background thread"""
        if hasattr(self, '_polling_thread') and self._polling_thread.isRunning():
            self._polling_thread.stop()

        if self.guardian_state:
            self._polling_thread = GuardianPollingThread(self.guardian_state.address)
            self._polling_thread.signals_updated.connect(self._handle_new_signals)
            self._polling_thread.polling_error.connect(self._handle_polling_error)
            self._polling_thread.update_processed_txids(self.guardian_state.processed_txids)
            self._polling_thread.start()
            print("[Guardian] Started background polling thread")

    def _handle_new_signals(self, signals):
        """Handle new signals from background thread - runs on main thread"""
        if not signals or not self.guardian_state:
            return

        try:
            # Sort by nonce to process in order
            signals.sort(key=lambda s: s['nonce'])
            print(f"[Guardian] Received {len(signals)} new signals from background thread")

            # Debug: Print all received signals
            for signal in signals:
                print(f"[Guardian] Signal received: nonce {signal['nonce']}, locked={signal['locked']}, payload='{signal['payload']}'")

            state_changed = False
            highest_nonce_applied = self.guardian_state.nonce

            for signal in signals:
                # Only process signals with nonces higher than our current state
                if signal['nonce'] > self.guardian_state.nonce:
                    print(f"[Guardian] Processing signal: nonce {signal['nonce']} > current {self.guardian_state.nonce}")
                    if self.guardian_state.apply_signal(signal):
                        state_changed = True
                        highest_nonce_applied = signal['nonce']
                        print(f"[Guardian] *** APPLIED SIGNAL *** nonce {signal['nonce']}, locked={signal['locked']}")
                    else:
                        print(f"[Guardian] Signal application failed for nonce {signal['nonce']}")
                else:
                    # Mark as processed even if nonce is old
                    self.guardian_state.processed_txids.add(signal['txid'])
                    print(f"[Guardian] Ignoring old signal: nonce {signal['nonce']} <= current {self.guardian_state.nonce}")

            # Update background thread with new processed txids
            if hasattr(self, '_polling_thread'):
                self._polling_thread.update_processed_txids(self.guardian_state.processed_txids)

            if state_changed:
                print(f"[Guardian] State changed! New nonce: {self.guardian_state.nonce}, locked: {self.guardian_state.locked}")
                self._persist_state()
                self._update_status_widget()
                status = "LOCKED" if self.guardian_state.locked else "UNLOCKED"
                print(f"[Guardian] *** WALLET IS NOW {status} ***")

                # Handle tab click prevention
                if self.guardian_state.locked:
                    print("[Guardian] Applying lock protections")
                    self._start_tab_click_prevention()
                    self._patch_wallet_methods()
                else:
                    print("[Guardian] Removing lock protections")
                    self._stop_tab_click_prevention()
                    self._unpatch_wallet_methods()

                # Always show notification for state changes
                if self.main_window:
                    print(f"[Guardian] Showing state change notification: {status}")
                    msg = f"Guardian state changed!\n\nWallet is now: {status}\nNonce: {self.guardian_state.nonce}"
                    QMessageBox.information(self.main_window, "Guardian Update", msg)
                else:
                    print("[Guardian] Cannot show notification - no main_window")
            else:
                print(f"[Guardian] No state change - current nonce: {self.guardian_state.nonce}, locked: {self.guardian_state.locked}")

            # Mark startup as complete after first signal processing
            if not self._startup_sync_complete:
                print("[Guardian] Marking startup sync as complete")
                self._startup_sync_complete = True

        except Exception as e:
            print(f"[Guardian] Error handling signals: {e}")
            import traceback
            traceback.print_exc()

    def _handle_polling_error(self, error_msg):
        """Handle polling errors from background thread"""
        print(f"[Guardian] Background polling error: {error_msg}")

    def _force_immediate_sync(self):
        """Force immediate synchronous blockchain sync to prevent stale state security issues"""
        if not self.guardian_state:
            return

        print(f"[Guardian] SECURITY: Starting immediate sync - current nonce: {self.guardian_state.nonce}")

        try:
            # Synchronously fetch the latest signals to prevent security vulnerabilities
            signals = self._fetch_guardian_signals_sync()

            if signals:
                # Sort by nonce and apply all newer signals
                signals.sort(key=lambda s: s['nonce'])
                original_nonce = self.guardian_state.nonce
                original_locked = self.guardian_state.locked

                print(f"[Guardian] SECURITY SYNC: Found {len(signals)} signals, sorting by nonce...")
                for signal in signals:
                    print(f"[Guardian] SECURITY SYNC: Signal nonce {signal['nonce']}, locked={signal['locked']}, payload='{signal['payload']}'")

                applied_count = 0
                for signal in signals:
                    if signal['nonce'] > self.guardian_state.nonce:
                        if self.guardian_state.apply_signal(signal):
                            applied_count += 1
                            print(f"[Guardian] SECURITY SYNC: Applied signal nonce {signal['nonce']}, locked={signal['locked']}")

                if applied_count > 0:
                    print(f"[Guardian] SECURITY SYNC: Updated from nonce {original_nonce}->{self.guardian_state.nonce}, locked {original_locked}->{self.guardian_state.locked}")
                    self._persist_state()

                    # Apply protections immediately if now locked
                    if self.guardian_state.locked and not original_locked:
                        print("[Guardian] SECURITY SYNC: Wallet is now LOCKED - applying protections immediately")
                        self._start_tab_click_prevention()
                        self._patch_wallet_methods()
                else:
                    print(f"[Guardian] SECURITY SYNC: No signals applied - state unchanged at nonce {self.guardian_state.nonce}, locked={self.guardian_state.locked}")
            else:
                print(f"[Guardian] SECURITY SYNC: No signals fetched - network timeout or API issues")
                # IMPORTANT: Don't assume unlock on API failure - maintain existing state
                print(f"[Guardian] SECURITY SYNC: Maintaining existing state - nonce {self.guardian_state.nonce}, locked={self.guardian_state.locked}")

                # Apply protections if we think we're locked (safety first)
                if self.guardian_state.locked:
                    print("[Guardian] SECURITY SYNC: Applying protections for existing locked state")
                    self._start_tab_click_prevention()
                    self._patch_wallet_methods()

        except Exception as e:
            print(f"[Guardian] SECURITY SYNC ERROR: {e}")
            # On sync error, maintain existing state but apply protections if Guardian exists
            if self.guardian_state:
                print(f"[Guardian] SECURITY SYNC ERROR: Maintaining state due to sync failure - locked={self.guardian_state.locked}")
                # Be conservative - apply protections if we have any doubt
                if self.guardian_state.locked:
                    print("[Guardian] SECURITY SYNC ERROR: Applying protections due to sync failure")
                    self._start_tab_click_prevention()
                    self._patch_wallet_methods()

    def _fetch_guardian_signals_sync(self):
        """Synchronously fetch Guardian signals for immediate security sync"""
        try:
            print(f"[Guardian] SECURITY SYNC: Fetching signals for {self.guardian_state.address}")

            # Get transaction list synchronously
            url = f"https://mempool.space/testnet/api/address/{self.guardian_state.address}/txs"
            print(f"[Guardian] SECURITY SYNC: Requesting {url}")
            response = requests.get(url, timeout=15)
            if response.status_code != 200:
                print(f"[Guardian] SECURITY SYNC: Failed to fetch transactions, status {response.status_code}")
                return []

            txs = response.json()
            print(f"[Guardian] SECURITY SYNC: Found {len(txs)} total transactions")

            # Debug: Print first few transaction IDs
            for i, tx in enumerate(txs[:5]):
                print(f"[Guardian] SECURITY SYNC: TX {i}: {tx.get('txid', 'NO_TXID')}")

            # Process all transactions to find signals
            signals = []
            processed_count = 0
            for tx in txs[:30]:  # Check more transactions for security sync
                try:
                    tx_hash = tx['txid']
                    processed_count += 1

                    print(f"[Guardian] SECURITY SYNC: Processing tx {processed_count}/{min(30, len(txs))}: {tx_hash}")

                    # Get transaction hex
                    hex_url = f"https://mempool.space/testnet/api/tx/{tx_hash}/hex"
                    hex_response = requests.get(hex_url, timeout=10)
                    if hex_response.status_code != 200:
                        print(f"[Guardian] SECURITY SYNC: Failed to get hex for {tx_hash}, status {hex_response.status_code}")
                        continue

                    raw_tx = hex_response.text.strip()
                    print(f"[Guardian] SECURITY SYNC: Got hex data for {tx_hash}, length: {len(raw_tx)}")

                    try:
                        transaction = Transaction(raw_tx)
                        print(f"[Guardian] SECURITY SYNC: Parsed transaction {tx_hash}")

                        # Debug: Print all outputs
                        outputs = transaction.outputs()
                        print(f"[Guardian] SECURITY SYNC: Transaction has {len(outputs)} outputs")
                        for j, output in enumerate(outputs):
                            script = output.scriptpubkey
                            print(f"[Guardian] SECURITY SYNC: Output {j}: script length {len(script) if script else 0}")
                            if script and len(script) > 0:
                                print(f"[Guardian] SECURITY SYNC: Output {j}: script[0] = 0x{script[0]:02x}")
                                if script[0] == 0x6a:  # OP_RETURN
                                    print(f"[Guardian] SECURITY SYNC: *** Output {j} is OP_RETURN ***")
                                    if len(script) > 1:
                                        data = script[1:]
                                        print(f"[Guardian] SECURITY SYNC: OP_RETURN data length: {len(data)}")
                                        if len(data) > 0:
                                            push_len = data[0]
                                            print(f"[Guardian] SECURITY SYNC: Push length: {push_len}")
                                            if len(data) >= push_len + 1:
                                                payload = data[1:1 + push_len]
                                                try:
                                                    payload_str = payload.decode('ascii')
                                                    print(f"[Guardian] SECURITY SYNC: Payload string: '{payload_str}'")
                                                except Exception as decode_error:
                                                    print(f"[Guardian] SECURITY SYNC: Decode error: {decode_error}")

                    except Exception as parse_error:
                        print(f"[Guardian] SECURITY SYNC: Failed to parse transaction {tx_hash}: {parse_error}")
                        continue

                    signal = extract_signal_from_tx(transaction)
                    if signal:
                        status = tx.get('status', {})
                        signal['height'] = status.get('block_height', 0) if status.get('confirmed', False) else 0
                        signal['is_mempool'] = (signal['height'] == 0)
                        signals.append(signal)
                        print(f"[Guardian] SECURITY SYNC: *** FOUND SIGNAL *** nonce {signal['nonce']}, locked={signal['locked']}, payload='{signal['payload']}'")
                    else:
                        print(f"[Guardian] SECURITY SYNC: No signal found in transaction {tx_hash}")

                except Exception as e:
                    print(f"[Guardian] SECURITY SYNC: Error processing tx {tx.get('txid', 'unknown')}: {e}")
                    import traceback
                    traceback.print_exc()

            print(f"[Guardian] SECURITY SYNC: Completed processing {processed_count} transactions, found {len(signals)} signals")
            return signals

        except Exception as e:
            print(f"[Guardian] SECURITY SYNC: Error fetching signals: {e}")
            import traceback
            traceback.print_exc()
            return []

    def _add_guardian_menu(self):
        """Add Guardian Settings to Tools menu with comprehensive error handling"""
        try:
            print(f"[Guardian] _add_guardian_menu called, menu_added={self._menu_added}")

            if self._menu_added:
                print("[Guardian] Menu already added, skipping")
                return True

            if not self.main_window:
                print("[Guardian] ERROR: main_window is None")
                return False

            print(f"[Guardian] main_window exists: {self.main_window}")
            print(f"[Guardian] main_window type: {type(self.main_window)}")

            # Check if main_window has the expected attributes
            if not hasattr(self.main_window, 'menuBar'):
                print("[Guardian] ERROR: main_window has no menuBar method")
                return False

            menu_bar = self.main_window.menuBar()
            if not menu_bar:
                print("[Guardian] ERROR: menuBar() returned None")
                return False

            print(f"[Guardian] Got menu bar: {menu_bar}")

            # Find Tools menu
            tools_menu = None
            menu_actions = menu_bar.actions()
            print(f"[Guardian] Found {len(menu_actions)} menu bar actions:")

            for i, action in enumerate(menu_actions):
                action_text = action.text()
                print(f"[Guardian]   {i}: '{action_text}'")
                if "tools" in action_text.lower() or "tool" in action_text.lower():
                    tools_menu = action.menu()
                    print(f"[Guardian] ✓ Found Tools menu: {action_text}")
                    break

            if not tools_menu:
                print("[Guardian] No Tools menu found, creating one...")
                # Create Tools menu if it doesn't exist
                tools_menu = menu_bar.addMenu("&Tools")
                print("[Guardian] Created new Tools menu")
            else:
                print("[Guardian] Using existing Tools menu")

            # Check if Guardian Settings already exists
            existing_actions = tools_menu.actions()
            for action in existing_actions:
                if "Guardian Settings" in action.text():
                    print("[Guardian] Guardian Settings already exists in menu")
                    self._menu_added = True
                    return True

            # Create Guardian Settings action
            print("[Guardian] Creating Guardian Settings action...")
            action = QAction("Guardian Settings", self.main_window)
            action.triggered.connect(self.show_guardian_dialog)

            # Add to Tools menu
            tools_menu.addAction(action)
            print("[Guardian] Added Guardian Settings action to Tools menu")

            self._menu_added = True
            return True

        except Exception as e:
            print(f"[Guardian] Error in _add_guardian_menu: {e}")
            import traceback
            traceback.print_exc()
            return False

    @hook
    def send_tx(self, wallet: Abstract_Wallet, tx: Transaction):
        """Hook to block transactions when Guardian is locked - final safety check"""
        if self.guardian_state and not self.guardian_state.disabled and self.guardian_state.locked:
            if self.main_window:
                QMessageBox.critical(self.main_window, "Transaction Blocked",
                    "Transaction blocked: Guardian is locked.\n\n"
                    f"Guardian Address: {self.guardian_state.address}\n"
                    f"Current Nonce: {self.guardian_state.nonce}\n\n"
                    "An unlock signal must be received before spending is allowed.")
            raise Exception("Transaction blocked: Guardian is locked")

    @hook
    def create_tx(self, wallet: Abstract_Wallet, outputs, fee, change_addr, domain, unsigned, rbf, password, locktime, sign):
        """Hook to block transaction creation when Guardian is locked"""
        if self.guardian_state and not self.guardian_state.disabled and self.guardian_state.locked:
            if self.main_window:
                QMessageBox.critical(self.main_window, "Transaction Blocked",
                    "Transaction creation blocked: Guardian is locked.\n\n"
                    f"Guardian Address: {self.guardian_state.address}\n"
                    f"Current Nonce: {self.guardian_state.nonce}\n\n"
                    "An unlock signal must be received before spending is allowed.")
            raise Exception("Transaction creation blocked: Guardian is locked")

    def _start_tab_click_prevention(self):
        """Start tab click prevention instead of button disabling"""
        if not hasattr(self, '_tab_click_filter'):
            self._tab_click_filter = GuardianTabClickFilter(self)
            self.main_window.tabs.tabBar().installEventFilter(self._tab_click_filter)

        # Grey out the Send tab visually
        self._grey_out_send_tab()
        print("[Guardian] Enabled tab click prevention")

    def _stop_tab_click_prevention(self):
        """Stop tab click prevention and restore normal appearance"""
        if hasattr(self, '_tab_click_filter'):
            self.main_window.tabs.tabBar().removeEventFilter(self._tab_click_filter)
            delattr(self, '_tab_click_filter')

        # Restore normal tab appearance
        self._restore_send_tab_appearance()
        print("[Guardian] Disabled tab click prevention")

    def _grey_out_send_tab(self):
        """Grey out Send tab visually but keep UI intact"""
        try:
            send_tab_index = self._find_send_tab_index()
            if send_tab_index >= 0:
                # Store original colors if not already stored
                if not hasattr(self, '_original_tab_colors'):
                    self._original_tab_colors = {}

                if send_tab_index not in self._original_tab_colors:
                    self._original_tab_colors[send_tab_index] = {
                        'text_color': self.main_window.tabs.tabBar().tabTextColor(send_tab_index),
                        'tooltip': self.main_window.tabs.tabToolTip(send_tab_index)
                    }

                # Grey out tab
                self.main_window.tabs.tabBar().setTabTextColor(send_tab_index, Qt.GlobalColor.gray)
                self.main_window.tabs.setTabToolTip(send_tab_index,
                    "Transactions prohibited: Guardian Locked\nClick to view details")

                print(f"[Guardian] Greyed out Send tab at index {send_tab_index}")

        except Exception as e:
            print(f"[Guardian] Error greying out Send tab: {e}")

    def _restore_send_tab_appearance(self):
        """Restore Send tab to normal appearance"""
        try:
            send_tab_index = self._find_send_tab_index()
            if send_tab_index >= 0 and hasattr(self, '_original_tab_colors'):
                original = self._original_tab_colors.get(send_tab_index)
                if original:
                    # Restore original colors
                    self.main_window.tabs.tabBar().setTabTextColor(
                        send_tab_index, original['text_color'])
                    self.main_window.tabs.setTabToolTip(
                        send_tab_index, original['tooltip'])

                print(f"[Guardian] Restored Send tab appearance at index {send_tab_index}")

        except Exception as e:
            print(f"[Guardian] Error restoring Send tab: {e}")

    def _find_send_tab_index(self):
        """Find the index of the Send tab"""
        for i in range(self.main_window.tabs.count()):
            tab_text = self.main_window.tabs.tabText(i).lower()
            if 'send' in tab_text:
                return i
        return -1

    def show_guardian_dialog(self):
        try:
            print("[Guardian] show_guardian_dialog called")
            print(f"[Guardian] Guardian state exists: {self.guardian_state is not None}")
            if self.guardian_state:
                print(f"[Guardian] Guardian address: {self.guardian_state.address}")
                print(f"[Guardian] Guardian locked: {self.guardian_state.locked}")
                print(f"[Guardian] Guardian nonce: {self.guardian_state.nonce}")

            # Force an immediate background poll to ensure we have latest state
            if hasattr(self, '_polling_thread') and self._polling_thread.isRunning():
                print("[Guardian] Forcing immediate background poll before dialog")
                self._polling_thread.msleep(0)  # Wake up background thread

                # Brief pause to allow background thread to process
                QTimer.singleShot(500, self._show_dialog_with_current_state)
                return
            else:
                self._show_dialog_with_current_state()

        except Exception as e:
            print(f"[Guardian] Error in dialog: {e}")
            import traceback
            traceback.print_exc()

    def _show_dialog_with_current_state(self):
        """Show dialog after ensuring we have current state"""
        try:
            print(f"[Guardian] Showing dialog with current state - Guardian exists: {self.guardian_state is not None}")
            if self.guardian_state:
                print(f"[Guardian] Guardian details - address: {self.guardian_state.address}, disabled: {getattr(self.guardian_state, 'disabled', False)}")

            d = QDialog(self.main_window)
            d.setWindowTitle("Guardian Address Settings")
            d.setMinimumWidth(650)
            d.setMinimumHeight(450)
            layout = QVBoxLayout(d)
            layout.setSpacing(25)
            layout.setContentsMargins(30, 30, 30, 30)

            # Header
            header = QLabel("Guardian Address Configuration")
            header.setStyleSheet("font-size: 22px; font-weight: bold; margin-bottom: 20px; color: #2c3e50;")
            layout.addWidget(header)

            # Check if we have an ACTIVE Guardian (not disabled)
            has_active_guardian = (self.guardian_state is not None and
                                 not getattr(self.guardian_state, 'disabled', False))

            print(f"[Guardian] Has active Guardian: {has_active_guardian}")

            if has_active_guardian:
                # Guardian exists and is active - show status information
                print("[Guardian] Creating status section with current active Guardian state")
                self._create_status_section(layout)

                # Action buttons (conditional based on lock state)
                self._create_action_buttons_existing(layout, d)
            else:
                # No active Guardian configured - show setup section
                print("[Guardian] Creating setup section - no active Guardian")
                self._create_setup_section(layout, d)

            d.exec()

        except Exception as e:
            print(f"[Guardian] Error showing dialog: {e}")
            import traceback
            traceback.print_exc()

    def _create_status_section(self, layout):
        """Create the status information section for existing Guardian"""
        status_frame = QFrame()
        status_frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border: 2px solid #dee2e6;
                border-radius: 12px;
                padding: 20px;
                margin: 10px 0;
            }
        """)
        status_layout = QVBoxLayout(status_frame)
        status_layout.setSpacing(15)

        # Status header with colored indicator
        status_header_layout = QHBoxLayout()

        status_title = QLabel("Guardian Status")
        status_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;")
        status_header_layout.addWidget(status_title)

        status_header_layout.addStretch()

        # Large status indicator
        if self.guardian_state.locked:
            status_indicator = QLabel("LOCKED")
            status_indicator.setStyleSheet("""
                font-size: 16px;
                font-weight: bold;
                color: white;
                background-color: #dc3545;
                padding: 8px 16px;
                border-radius: 6px;
            """)
        else:
            status_indicator = QLabel("UNLOCKED")
            status_indicator.setStyleSheet("""
                font-size: 16px;
                font-weight: bold;
                color: white;
                background-color: #28a745;
                padding: 8px 16px;
                border-radius: 6px;
            """)

        status_header_layout.addWidget(status_indicator)
        status_layout.addLayout(status_header_layout)

        # Information grid using snapshot to avoid race conditions
        info_grid = QFrame()
        info_grid.setStyleSheet("background-color: white; border-radius: 8px; padding: 15px;")
        grid_layout = QVBoxLayout(info_grid)

        try:
            print("[Guardian] Creating text display using QTextEdit...")

            # Capture state as a snapshot to prevent race conditions
            snapshot_address = self.guardian_state.address
            snapshot_nonce = self.guardian_state.nonce
            snapshot_locked = self.guardian_state.locked
            snapshot_processed_txids = set(self.guardian_state.processed_txids)
            snapshot_processed_count = len(snapshot_processed_txids)
            snapshot_history = list(self.guardian_state.history)

            text_content = []
            text_content.append(f"Guardian Address: {snapshot_address[:15]}...{snapshot_address[-15:]}")
            text_content.append(f"Current Nonce: {snapshot_nonce}")
            text_content.append(f"Processed Signals: {snapshot_processed_count}")

            if snapshot_history:
                last_update = max(snapshot_history, key=lambda x: x['nonce'])
                last_time = datetime.datetime.fromtimestamp(last_update['observed_time']).strftime('%Y-%m-%d %H:%M:%S')
                text_content.append(f"Last Updated: {last_time}")
            else:
                text_content.append("Last Updated: Never")

            thread_running = hasattr(self, '_polling_thread') and self._polling_thread.isRunning()
            monitoring_status = "Active" if thread_running else "Inactive"
            text_content.append(f"Monitoring: {monitoring_status}")

            text_content.append(f"Lock State: {'LOCKED' if snapshot_locked else 'UNLOCKED'}")

            # Create a simple text edit widget
            text_widget = QTextEdit()
            text_widget.setPlainText("\n".join(text_content))
            text_widget.setReadOnly(True)
            text_widget.setMaximumHeight(180)
            text_widget.setStyleSheet("""
                QTextEdit {
                    font-family: monospace;
                    font-size: 13px;
                    background-color: white;
                    color: black;
                    border: 1px solid #ccc;
                    padding: 8px;
                }
            """)

            grid_layout.addWidget(text_widget)

        except Exception as e:
            print(f"[Guardian] Error creating text widget: {e}")
            # Fallback to basic label
            fallback_text = f"Guardian: {self.guardian_state.address[:20]}..., Nonce: {self.guardian_state.nonce}"
            fallback_label = QLabel(fallback_text)
            fallback_label.setStyleSheet("color: black; background: white; padding: 10px; font-family: monospace;")
            grid_layout.addWidget(fallback_label)

        status_layout.addWidget(info_grid)
        layout.addWidget(status_frame)

    def _create_setup_section(self, layout, dialog):
        """Create the Guardian setup section for new configuration"""
        setup_frame = QFrame()
        setup_frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border: 2px solid #007bff;
                border-radius: 12px;
                padding: 25px;
                margin: 10px 0;
            }
        """)
        setup_layout = QVBoxLayout(setup_frame)
        setup_layout.setSpacing(20)

        setup_title = QLabel("Configure Guardian Address")
        setup_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #007bff; margin-bottom: 10px;")
        setup_layout.addWidget(setup_title)

        description = QLabel(
            "Enter a Bitcoin address that will control the lock/unlock state of this wallet. "
            "The Guardian Address must be separate from your spending wallet and should have "
            "been instantiated with an unlock signal (guardv1.Lock=false#1)."
        )
        description.setStyleSheet("color: #6c757d; line-height: 1.4; margin-bottom: 15px;")
        description.setWordWrap(True)
        setup_layout.addWidget(description)

        self.addr_edit = QLineEdit()
        self.addr_edit.setPlaceholderText("Enter Guardian address (e.g., tb1q...)")
        self.addr_edit.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                font-size: 13px;
                border: 2px solid #ced4da;
                border-radius: 6px;
                background-color: white;
                font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            }
            QLineEdit:focus {
                border-color: #007bff;
                outline: none;
            }
        """)
        setup_layout.addWidget(self.addr_edit)

        layout.addWidget(setup_frame)

        # Setup action buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #545b62;
            }
        """)
        cancel_btn.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_btn)

        save_btn = QPushButton("Configure Guardian")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #007bff;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
        """)
        save_btn.setDefault(True)
        save_btn.clicked.connect(lambda: self._save_guardian_from_dialog(self.addr_edit.text().strip(), dialog))
        button_layout.addWidget(save_btn)

        layout.addLayout(button_layout)

    def _create_action_buttons_existing(self, layout, dialog):
        """Create action buttons for existing Guardian configuration"""
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        # Only show Remove button if Guardian is unlocked
        if not self.guardian_state.locked:
            remove_btn = QPushButton("Remove Guardian")
            remove_btn.setStyleSheet("""
                QPushButton {
                    background-color: #dc3545;
                    color: white;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 6px;
                    font-weight: bold;
                    min-width: 120px;
                }
                QPushButton:hover {
                    background-color: #c82333;
                }
            """)
            remove_btn.clicked.connect(lambda: self._remove_guardian(dialog))
            button_layout.addWidget(remove_btn)
        else:
            # Show disabled remove button with explanation
            remove_btn = QPushButton("Remove Guardian")
            remove_btn.setStyleSheet("""
                QPushButton {
                    background-color: #e9ecef;
                    color: #6c757d;
                    padding: 10px 20px;
                    border: 2px solid #dee2e6;
                    border-radius: 6px;
                    font-weight: bold;
                    min-width: 120px;
                }
            """)
            remove_btn.setEnabled(False)
            remove_btn.setToolTip("Guardian must be unlocked before removal")
            button_layout.addWidget(remove_btn)

        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
        """)
        close_btn.clicked.connect(dialog.accept)
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout)

    def _save_guardian_from_dialog(self, address, dialog):
        """Save Guardian configuration with validation"""
        if not address:
            QMessageBox.warning(dialog, "Guardian", "Please enter a Guardian address")
            return

        # Prevent saving if an ACTIVE Guardian already exists
        if self.guardian_state and not getattr(self.guardian_state, 'disabled', False):
            QMessageBox.warning(dialog, "Guardian",
                "A Guardian Address is already configured.\n\n"
                "Per the Guardian Address standard, only one Guardian Address "
                "is allowed per wallet. Remove the existing Guardian first.")
            return

        try:
            print(f"[Guardian] VALIDATION: Starting validation for address: {address}")
            old_state = self.guardian_state
            self.guardian_state = GuardianState(address)

            # Validate by performing immediate sync with detailed logging
            print(f"[Guardian] VALIDATION: About to call _force_immediate_sync...")
            self._force_immediate_sync()
            print(f"[Guardian] VALIDATION: After sync - nonce: {self.guardian_state.nonce}, locked: {self.guardian_state.locked}")

            # Brief pause to allow any background processes to settle
            QTimer.singleShot(2000, lambda: self._complete_guardian_setup(address, dialog, old_state))

        except Exception as e:
            print(f"[Guardian] VALIDATION ERROR: {e}")
            import traceback
            traceback.print_exc()
            self.guardian_state = old_state
            QMessageBox.warning(dialog, "Error", f"Failed to configure Guardian: {str(e)}")

    def _complete_guardian_setup(self, address, dialog, old_state):
        """Complete Guardian setup after background validation"""
        try:
            print(f"[Guardian] SETUP VALIDATION: Guardian state - nonce: {self.guardian_state.nonce}, locked: {self.guardian_state.locked}")

            # Check if Guardian was properly instantiated and unlocked
            if self.guardian_state.nonce == 0:
                print("[Guardian] SETUP VALIDATION: Failed - Guardian not instantiated (nonce=0)")
                self.guardian_state = old_state
                QMessageBox.warning(dialog, "Invalid Guardian",
                    "This address has not been instantiated as a Guardian Address.\n\n"
                    "The address must broadcast at least one Guardian signal "
                    "before it can be used as a Guardian.")
                return

            if self.guardian_state.locked:
                print(f"[Guardian] SETUP VALIDATION: Failed - Guardian is locked at nonce {self.guardian_state.nonce}")
                self.guardian_state = old_state
                QMessageBox.warning(dialog, "Guardian Locked",
                    "This Guardian Address is currently locked.\n\n"
                    "Only unlocked Guardian Addresses can be configured to prevent "
                    "accidentally locking your wallet.")
                return

            print(f"[Guardian] SETUP VALIDATION: Success - Guardian is unlocked at nonce {self.guardian_state.nonce}")

            # Save to separate Guardian config file
            guardian_config = {
                'address': address,
                'state': self.guardian_state.serialize(),
                'disabled': False
            }

            if self._save_guardian_config(guardian_config):
                print(f"[Guardian] Saved new Guardian to config file")
            else:
                raise Exception("Failed to save Guardian configuration file")

            self.start_polling()
            self._update_status_widget()

            QMessageBox.information(dialog, "Success",
                f"Guardian configured successfully!\n\n"
                f"Address: {address}\n"
                f"Status: Unlocked\n"
                f"Nonce: {self.guardian_state.nonce}")
            dialog.accept()

        except Exception as e:
            print(f"[Guardian] SETUP VALIDATION ERROR: {e}")
            import traceback
            traceback.print_exc()
            self.guardian_state = old_state
            QMessageBox.warning(dialog, "Error", f"Failed to configure Guardian: {str(e)}")

    def _remove_guardian(self, dialog):
        """Remove guardian configuration by deleting config file"""
        reply = QMessageBox.question(dialog, "Confirm Removal",
            "Are you sure you want to remove the Guardian configuration?\n\n"
            "This will disable Guardian protection for this wallet.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Stop background polling thread first
                if hasattr(self, '_polling_thread') and self._polling_thread.isRunning():
                    print("[Guardian] Stopping polling thread for removal")
                    self._polling_thread.stop()

                # Stop any tab click prevention
                if hasattr(self, '_tab_click_filter'):
                    self._stop_tab_click_prevention()

                # Clear state from memory
                if self.guardian_state:
                    print(f"[Guardian] Removing Guardian for address: {self.guardian_state.address}")

                self.guardian_state = None

                # Remove the separate Guardian config file
                if self._remove_guardian_config():
                    print("[Guardian] ✓ Successfully removed Guardian configuration file")
                else:
                    raise Exception("Failed to remove Guardian configuration file")

                # Update UI
                self._update_status_widget()

                QMessageBox.information(dialog, "Guardian",
                    "Guardian configuration removed successfully.")
                dialog.accept()
                print("[Guardian] Guardian removal completed successfully")

            except Exception as e:
                print(f"[Guardian] Error removing guardian: {e}")
                import traceback
                traceback.print_exc()
                QMessageBox.warning(dialog, "Error", f"Error removing guardian: {str(e)}")

    def _update_status_widget(self):
        """Update status widget and refresh UI - must run on main thread"""
        if not self.main_window:
            return

        # Remove existing widget
        if self.status_widget:
            self.main_window.statusBar().removeWidget(self.status_widget)
            self.status_widget = None

        # Add new widget if guardian configured
        if self.guardian_state:
            self.status_widget = QLabel()
            if self.guardian_state.locked:
                self.status_widget.setText("Guardian: Locked")
                self.status_widget.setStyleSheet("color: red; font-weight: bold;")
                self.status_widget.setToolTip("Guardian is locked and spending is prohibited")
            else:
                self.status_widget.setText("Guardian: Unlocked")
                self.status_widget.setStyleSheet("color: green; font-weight: bold;")
                self.status_widget.setToolTip("Guardian is unlocked and balance may be spent")
            self.status_widget.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.main_window.statusBar().addPermanentWidget(self.status_widget)

    def _patch_wallet_methods(self):
        """Patch wallet methods to block transactions when Guardian is locked"""
        if not self._wallet:
            return

        # Store original methods if not already stored
        if not hasattr(self._wallet, '_guardian_original_sign_transaction'):
            self._wallet._guardian_original_sign_transaction = self._wallet.sign_transaction
            self._wallet._guardian_original_send_transaction = getattr(self._wallet, 'send_transaction', None)

        # Replace with guarded versions
        def guardian_sign_transaction(*args, **kwargs):
            if self.guardian_state and self.guardian_state.locked:
                print("[Guardian] BLOCKED: sign_transaction called while Guardian locked")
                raise Exception("SECURITY: Transaction signing blocked by Guardian - wallet is locked")
            return self._wallet._guardian_original_sign_transaction(*args, **kwargs)

        def guardian_send_transaction(*args, **kwargs):
            if self.guardian_state and self.guardian_state.locked:
                print("[Guardian] BLOCKED: send_transaction called while Guardian locked")
                raise Exception("SECURITY: Transaction broadcast blocked by Guardian - wallet is locked")
            return self._wallet._guardian_original_send_transaction(*args, **kwargs)

        self._wallet.sign_transaction = guardian_sign_transaction
        if self._wallet._guardian_original_send_transaction:
            self._wallet.send_transaction = guardian_send_transaction

    def _unpatch_wallet_methods(self):
        """Restore original wallet methods"""
        if not self._wallet:
            print("[Guardian] Cannot unpatch - no wallet")
            return

        try:
            if hasattr(self._wallet, '_guardian_original_sign_transaction'):
                self._wallet.sign_transaction = self._wallet._guardian_original_sign_transaction
                delattr(self._wallet, '_guardian_original_sign_transaction')
                print("[Guardian] Restored original sign_transaction")

            if hasattr(self._wallet, '_guardian_original_send_transaction'):
                if self._wallet._guardian_original_send_transaction:
                    self._wallet.send_transaction = self._wallet._guardian_original_send_transaction
                delattr(self._wallet, '_guardian_original_send_transaction')
                print("[Guardian] Restored original send_transaction")

        except Exception as e:
            print(f"[Guardian] Error unpatching wallet methods: {e}")
            import traceback
            traceback.print_exc()

    def _persist_state(self):
        """Persist Guardian state to config file"""
        if self.guardian_state:
            try:
                guardian_config = {
                    'address': self.guardian_state.address,
                    'state': self.guardian_state.serialize(),
                    'disabled': False
                }

                if self._save_guardian_config(guardian_config):
                    print("[Guardian] State persisted to config file")
                else:
                    print("[Guardian] Error persisting state to config file")
            except Exception as e:
                print(f"[Guardian] Error persisting state: {e}")