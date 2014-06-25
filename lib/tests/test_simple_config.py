import sys
import unittest
import tempfile
import shutil

from StringIO import StringIO
from lib.simple_config import SimpleConfig


class Test_SimpleConfig(unittest.TestCase):

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

    def test_simple_config_command_line_overrides_everything(self):
        """Options passed by command line override all other configuration
        sources"""
        fake_read_system = lambda : {"electrum_path": "a"}
        fake_read_user = lambda _: {"electrum_path": "b"}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options=self.options,
                              read_system_config_function=fake_read_system,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        self.assertEqual(self.options.get("electrum_path"),
                         config.get("electrum_path"))

    def test_simple_config_system_config_overrides_user_config(self):
        """Options passed in system config override user config."""
        fake_read_system = lambda : {"electrum_path": self.electrum_dir}
        fake_read_user = lambda _: {"electrum_path": "b"}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options=None,
                              read_system_config_function=fake_read_system,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        self.assertEqual(self.options.get("electrum_path"),
                         config.get("electrum_path"))

    def test_simple_config_user_config_is_used_if_others_arent_specified(self):
        """Options passed by command line override all other configuration
        sources"""
        fake_read_system = lambda : {}
        fake_read_user = lambda _: {"electrum_path": self.electrum_dir}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options=None,
                              read_system_config_function=fake_read_system,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        self.assertEqual(self.options.get("electrum_path"),
                         config.get("electrum_path"))

    def test_cannot_set_options_passed_by_command_line(self):
        fake_read_system = lambda : {}
        fake_read_user = lambda _: {"electrum_path": "b"}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options=self.options,
                              read_system_config_function=fake_read_system,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        config.set_key("electrum_path", "c")
        self.assertEqual(self.options.get("electrum_path"),
                         config.get("electrum_path"))

    def test_cannot_set_options_from_system_config(self):
        fake_read_system = lambda : {"electrum_path": self.electrum_dir}
        fake_read_user = lambda _: {}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options={},
                              read_system_config_function=fake_read_system,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        config.set_key("electrum_path", "c")
        self.assertEqual(self.options.get("electrum_path"),
                         config.get("electrum_path"))

    def test_can_set_options_set_in_user_config(self):
        another_path = tempfile.mkdtemp()
        fake_read_system = lambda : {}
        fake_read_user = lambda _: {"electrum_path": self.electrum_dir}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options={},
                              read_system_config_function=fake_read_system,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        config.set_key("electrum_path", another_path)
        self.assertEqual(another_path, config.get("electrum_path"))
