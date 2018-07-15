import ast
import sys
import os
import unittest
import tempfile
import shutil

from io import StringIO
from electrum_ltc.simple_config import (SimpleConfig, read_user_config)

from . import SequentialTestCase


class Test_SimpleConfig(SequentialTestCase):

    def setUp(self):
        super(Test_SimpleConfig, self).setUp()
        # make sure "read_user_config" and "user_dir" return a temporary directory.
        self.electrum_dir = tempfile.mkdtemp()
        # Do the same for the user dir to avoid overwriting the real configuration
        # for development machines with electrum installed :)
        self.user_dir = tempfile.mkdtemp()

        self.options = {"electrum_path": self.electrum_dir}
        self._saved_stdout = sys.stdout
        self._stdout_buffer = StringIO()
        sys.stdout = self._stdout_buffer

    def tearDown(self):
        super(Test_SimpleConfig, self).tearDown()
        # Remove the temporary directory after each test (to make sure we don't
        # pollute /tmp for nothing.
        shutil.rmtree(self.electrum_dir)
        shutil.rmtree(self.user_dir)

        # Restore the "real" stdout
        sys.stdout = self._saved_stdout

    def test_simple_config_key_rename(self):
        """auto_cycle was renamed auto_connect"""
        fake_read_user = lambda _: {"auto_cycle": True}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options=self.options,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        self.assertEqual(config.get("auto_connect"), True)
        self.assertEqual(config.get("auto_cycle"), None)
        fake_read_user = lambda _: {"auto_connect": False, "auto_cycle": True}
        config = SimpleConfig(options=self.options,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        self.assertEqual(config.get("auto_connect"), False)
        self.assertEqual(config.get("auto_cycle"), None)

    def test_simple_config_command_line_overrides_everything(self):
        """Options passed by command line override all other configuration
        sources"""
        fake_read_user = lambda _: {"electrum_path": "b"}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options=self.options,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        self.assertEqual(self.options.get("electrum_path"),
                         config.get("electrum_path"))

    def test_simple_config_user_config_is_used_if_others_arent_specified(self):
        """If no system-wide configuration and no command-line options are
        specified, the user configuration is used instead."""
        fake_read_user = lambda _: {"electrum_path": self.electrum_dir}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options={},
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        self.assertEqual(self.options.get("electrum_path"),
                         config.get("electrum_path"))

    def test_cannot_set_options_passed_by_command_line(self):
        fake_read_user = lambda _: {"electrum_path": "b"}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options=self.options,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        config.set_key("electrum_path", "c")
        self.assertEqual(self.options.get("electrum_path"),
                         config.get("electrum_path"))

    def test_can_set_options_set_in_user_config(self):
        another_path = tempfile.mkdtemp()
        fake_read_user = lambda _: {"electrum_path": self.electrum_dir}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options={},
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        config.set_key("electrum_path", another_path)
        self.assertEqual(another_path, config.get("electrum_path"))

    def test_user_config_is_not_written_with_read_only_config(self):
        """The user config does not contain command-line options when saved."""
        fake_read_user = lambda _: {"something": "a"}
        read_user_dir = lambda : self.user_dir
        self.options.update({"something": "c"})
        config = SimpleConfig(options=self.options,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        config.save_user_config()
        contents = None
        with open(os.path.join(self.electrum_dir, "config"), "r") as f:
            contents = f.read()
        result = ast.literal_eval(contents)
        result.pop('config_version', None)
        self.assertEqual({"something": "a"}, result)

    def test_depth_target_to_fee(self):
        config = SimpleConfig(self.options)
        config.mempool_fees = [[49, 100110], [10, 121301], [6, 153731], [5, 125872], [1, 36488810]]
        self.assertEqual( 2 * 1000, config.depth_target_to_fee(1000000))
        self.assertEqual( 6 * 1000, config.depth_target_to_fee( 500000))
        self.assertEqual( 7 * 1000, config.depth_target_to_fee( 250000))
        self.assertEqual(11 * 1000, config.depth_target_to_fee( 200000))
        self.assertEqual(50 * 1000, config.depth_target_to_fee( 100000))
        config.mempool_fees = []
        self.assertEqual( 1 * 1000, config.depth_target_to_fee(10 ** 5))
        self.assertEqual( 1 * 1000, config.depth_target_to_fee(10 ** 6))
        self.assertEqual( 1 * 1000, config.depth_target_to_fee(10 ** 7))
        config.mempool_fees = [[1, 36488810]]
        self.assertEqual( 2 * 1000, config.depth_target_to_fee(10 ** 5))
        self.assertEqual( 2 * 1000, config.depth_target_to_fee(10 ** 6))
        self.assertEqual( 2 * 1000, config.depth_target_to_fee(10 ** 7))
        self.assertEqual( 1 * 1000, config.depth_target_to_fee(10 ** 8))
        config.mempool_fees = [[5, 125872], [1, 36488810]]
        self.assertEqual( 6 * 1000, config.depth_target_to_fee(10 ** 5))
        self.assertEqual( 2 * 1000, config.depth_target_to_fee(10 ** 6))
        self.assertEqual( 2 * 1000, config.depth_target_to_fee(10 ** 7))
        self.assertEqual( 1 * 1000, config.depth_target_to_fee(10 ** 8))

    def test_fee_to_depth(self):
        config = SimpleConfig(self.options)
        config.mempool_fees = [[49, 100000], [10, 120000], [6, 150000], [5, 125000], [1, 36000000]]
        self.assertEqual(100000, config.fee_to_depth(500))
        self.assertEqual(100000, config.fee_to_depth(50))
        self.assertEqual(100000, config.fee_to_depth(49))
        self.assertEqual(220000, config.fee_to_depth(48))
        self.assertEqual(220000, config.fee_to_depth(10))
        self.assertEqual(370000, config.fee_to_depth(9))
        self.assertEqual(370000, config.fee_to_depth(6.5))
        self.assertEqual(370000, config.fee_to_depth(6))
        self.assertEqual(495000, config.fee_to_depth(5.5))
        self.assertEqual(36495000, config.fee_to_depth(0.5))


class TestUserConfig(SequentialTestCase):

    def setUp(self):
        super(TestUserConfig, self).setUp()
        self._saved_stdout = sys.stdout
        self._stdout_buffer = StringIO()
        sys.stdout = self._stdout_buffer

        self.user_dir = tempfile.mkdtemp()

    def tearDown(self):
        super(TestUserConfig, self).tearDown()
        shutil.rmtree(self.user_dir)
        sys.stdout = self._saved_stdout

    def test_no_path_means_no_result(self):
       result = read_user_config(None)
       self.assertEqual({}, result)

    def test_path_without_config_file(self):
        """We pass a path but if does not contain a "config" file."""
        result = read_user_config(self.user_dir)
        self.assertEqual({}, result)

    def test_path_with_reprd_object(self):

        class something(object):
            pass

        thefile = os.path.join(self.user_dir, "config")
        payload = something()
        with open(thefile, "w") as f:
            f.write(repr(payload))

        result = read_user_config(self.user_dir)
        self.assertEqual({}, result)
