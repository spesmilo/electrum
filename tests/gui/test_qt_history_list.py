import importlib.util
import os
import subprocess
import sys
import textwrap
import unittest


class TestHistoryList(unittest.TestCase):
    def test_visible_refresh_skips_model_rebuild_when_history_is_unchanged(self):
        if importlib.util.find_spec("PyQt6") is None:
            self.skipTest("PyQt6 not available")

        env = os.environ.copy()
        env.setdefault("QT_QPA_PLATFORM", "offscreen")
        script = textwrap.dedent(
            r"""
            import datetime
            import threading

            from PyQt6.QtCore import QModelIndex
            from PyQt6.QtWidgets import QApplication, QLabel, QWidget

            from electrum.simple_config import SimpleConfig
            from electrum.util import OrderedDictWithIndex, Satoshis
            from electrum.gui.qt.history_list import HistoryList, HistoryModel


            class _Wallet:
                def __init__(self, tx_count):
                    self._labels = {f"txid{n}": f"label {n}" for n in range(tx_count)}
                    self.status_calls = 0

                def get_full_history(self, **kwargs):
                    history = OrderedDictWithIndex()
                    for n, txid in enumerate(self._labels):
                        history[txid] = {
                            "txid": txid,
                            "height": n + 1,
                            "confirmations": 10,
                            "timestamp": 1_700_000_000 + n,
                            "txpos_in_block": n,
                            "date": datetime.datetime(2024, 1, 1),
                            "label": self._labels[txid],
                            "value": Satoshis(1000 + n),
                            "bc_value": Satoshis(1000 + n),
                        }
                    return history

                def get_tx_status(self, txid, tx_mined_info):
                    self.status_calls += 1
                    return 9, "confirmed"


            class _MainWindow(QWidget):
                def __init__(self, tx_count):
                    super().__init__()
                    self.config = SimpleConfig({"electrum_path": "/tmp/electrum-test"})
                    self.wallet = _Wallet(tx_count)
                    self.fx = None
                    self.gui_thread = threading.current_thread()

                def format_amount(self, amount, **kwargs):
                    return str(amount)


            app = QApplication([])
            window = _MainWindow(100)
            history_model = HistoryModel(window)
            history_list = HistoryList(window, history_model)
            history_model.set_view(history_list)
            history_list.num_tx_label = QLabel()

            history_list._forced_update = True
            history_list.update()
            first_node = history_model._root.child(0)
            first_status_calls = window.wallet.status_calls
            assert history_model.rowCount(QModelIndex()) == 100
            assert history_list.num_tx_label.text() == "100 transactions"

            history_list.update()
            assert first_node is history_model._root.child(0)
            assert window.wallet.status_calls == first_status_calls

            window.wallet._labels["txid0"] = "updated"
            history_list.update()
            assert first_node is not history_model._root.child(0)
            assert history_model._root.child(0).get_data()["label"] == "updated"

            history_list._forced_update = False
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
