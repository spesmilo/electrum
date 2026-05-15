import importlib.util
import os
import subprocess
import sys
import textwrap
import unittest


class TestAddressList(unittest.TestCase):
    def test_visible_update_skips_model_rebuild_when_rows_are_unchanged(self):
        if importlib.util.find_spec("PyQt6") is None:
            self.skipTest("PyQt6 not available")

        env = os.environ.copy()
        env.setdefault("QT_QPA_PLATFORM", "offscreen")
        script = textwrap.dedent(
            r"""
            from PyQt6.QtWidgets import QApplication, QLabel, QWidget

            from electrum.simple_config import SimpleConfig
            from electrum.gui.qt.address_list import AddressList


            class _AddressDB:
                def __init__(self, wallet):
                    self.wallet = wallet

                def is_used(self, address):
                    return self.wallet._used.get(address, False)

                def get_address_history_len(self, address):
                    return self.wallet._history_len.get(address, 0)


            class _Wallet:
                def __init__(self, address_count):
                    self._addresses = [f"addr{n}" for n in range(address_count)]
                    self._balances = {address: (n, 0, 0)
                                      for n, address in enumerate(self._addresses)}
                    self._labels = {address: "" for address in self._addresses}
                    self._used = {address: False for address in self._addresses}
                    self._history_len = {address: 0 for address in self._addresses}
                    self.adb = _AddressDB(self)

                def get_receiving_addresses(self):
                    return self._addresses

                def get_change_addresses(self):
                    return []

                def get_addresses(self):
                    return self._addresses

                def get_all_known_addresses_beyond_gap_limit(self):
                    return set()

                def get_addr_balance(self, address):
                    return self._balances[address]

                def get_label_for_address(self, address):
                    return self._labels[address]

                def is_change(self, address):
                    return False

                def get_address_index(self, address):
                    return (self._addresses.index(address),)

                def get_address_path_str(self, address):
                    return None

                def is_frozen_address(self, address):
                    return False


            class _MainWindow(QWidget):
                def __init__(self, address_count):
                    super().__init__()
                    self.config = SimpleConfig({"electrum_path": "/tmp/electrum-test"})
                    self.wallet = _Wallet(address_count)
                    self.fx = None

                def format_amount(self, amount, **kwargs):
                    return str(amount)


            app = QApplication([])
            window = _MainWindow(100)
            address_list = AddressList(window)
            address_list.num_addr_label = QLabel()

            address_list._forced_update = True
            address_list.update()
            first_item = address_list.std_model.item(0, AddressList.Columns.ADDRESS)
            assert address_list.std_model.rowCount() == 100
            assert address_list.num_addr_label.text() == "100 addresses"

            address_list.update()
            assert first_item is address_list.std_model.item(0, AddressList.Columns.ADDRESS)

            window.wallet._labels["addr0"] = "updated"
            address_list.update()
            updated_item = address_list.std_model.item(0, AddressList.Columns.ADDRESS)
            assert first_item is not updated_item
            assert address_list.std_model.item(0, AddressList.Columns.LABEL).text() == "updated"

            address_list._forced_update = False
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
