import importlib.util
import os
import subprocess
import sys
import textwrap
import unittest


class TestUTXOList(unittest.TestCase):
    def test_hidden_update_defers_expensive_model_rebuild(self):
        if importlib.util.find_spec("PyQt6") is None:
            self.skipTest("PyQt6 not available")

        env = os.environ.copy()
        env.setdefault("QT_QPA_PLATFORM", "offscreen")
        script = textwrap.dedent(
            r"""
            from PyQt6.QtWidgets import QApplication, QLabel, QWidget

            from electrum.simple_config import SimpleConfig
            from electrum.gui.qt.utxo_list import UTXOList


            class _Prevout:
                def __init__(self, n):
                    self.txid = bytes([n % 256]) * 32
                    self.n = n

                def to_str(self):
                    return f"{self.txid.hex()}:{self.n}"


            class _Utxo:
                def __init__(self, n):
                    self.prevout = _Prevout(n)
                    self.short_id = f"{n}:0"
                    self.address = f"addr{n}"
                    self.block_height = n

                def value_sats(self):
                    return 1000


            class _AddressDB:
                def tx_height_to_sort_height(self, height):
                    return height


            class _Wallet:
                def __init__(self, utxo_count):
                    self.adb = _AddressDB()
                    self._utxos = [_Utxo(n) for n in range(utxo_count)]

                def get_utxos(self):
                    return self._utxos

                def get_num_parents(self, txid):
                    return 0

                def get_label_for_txid(self, txid):
                    return ""

                def is_frozen_address(self, address):
                    return False

                def is_frozen_coin(self, utxo):
                    return False


            class _MainWindow(QWidget):
                def __init__(self, utxo_count):
                    super().__init__()
                    self.config = SimpleConfig({"electrum_path": "/tmp/electrum-test"})
                    self.wallet = _Wallet(utxo_count)
                    self.coincontrol_msg = None

                def format_amount(self, amount, **kwargs):
                    return str(amount)

                def format_amount_and_units(self, amount):
                    return str(amount)

                def set_coincontrol_msg(self, msg):
                    self.coincontrol_msg = msg


            app = QApplication([])
            window = _MainWindow(100)
            utxo_list = UTXOList(window)
            utxo_list.num_coins_label = QLabel()

            utxo_list._forced_update = True
            utxo_list.update()
            utxo_list._forced_update = False
            first_item = utxo_list.std_model.item(0, UTXOList.Columns.OUTPOINT)
            assert utxo_list.std_model.rowCount() == 100

            utxo_list.update()

            assert first_item is utxo_list.std_model.item(0, UTXOList.Columns.OUTPOINT)
            assert utxo_list._pending_update
            assert len(utxo_list._utxo_dict) == 100
            assert utxo_list.num_coins_label.text() == "100 unspent transaction outputs"

            window.wallet._utxos = [_Utxo(n) for n in range(50)]
            utxo_list.update()
            assert utxo_list.std_model.rowCount() == 100
            assert len(utxo_list._utxo_dict) == 50
            assert utxo_list.num_coins_label.text() == "50 unspent transaction outputs"

            utxo_list._forced_update = True
            utxo_list.update()
            utxo_list._forced_update = False
            assert utxo_list.std_model.rowCount() == 50
            app.quit()
            """
        )

        result = subprocess.run(
            [sys.executable, "-c", script],
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(
            0,
            result.returncode,
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
