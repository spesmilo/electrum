import ast
import sys
import os
import unittest
import tempfile
import shutil
import json

from StringIO import StringIO
from lib.simple_config import (SimpleConfig, read_system_config,
                               read_user_config)


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

    def test_simple_config_key_rename(self):
        """auto_cycle was renamed auto_connect"""
        fake_read_system = lambda : {}
        fake_read_user = lambda _: {"auto_cycle": True}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options=self.options,
                              read_system_config_function=fake_read_system,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        self.assertEqual(config.get("auto_connect"), True)
        self.assertEqual(config.get("auto_cycle"), None)
        fake_read_user = lambda _: {"auto_connect": False, "auto_cycle": True}
        config = SimpleConfig(options=self.options,
                              read_system_config_function=fake_read_system,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        self.assertEqual(config.get("auto_connect"), False)
        self.assertEqual(config.get("auto_cycle"), None)

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

    def test_simple_config_user_config_overrides_system_config(self):
        """Options passed in user config override system config."""
        fake_read_system = lambda : {"electrum_path": self.electrum_dir}
        fake_read_user = lambda _: {"electrum_path": "b"}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options={},
                              read_system_config_function=fake_read_system,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        self.assertEqual("b", config.get("electrum_path"))

    def test_simple_config_system_config_ignored_if_portable(self):
        """If electrum is started with the "portable" flag, system
        configuration is completely ignored."""
        fake_read_system = lambda : {"some_key": "some_value"}
        fake_read_user = lambda _: {}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options={"portable": True},
                              read_system_config_function=fake_read_system,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        self.assertEqual(config.get("some_key"), None)

    def test_simple_config_user_config_is_used_if_others_arent_specified(self):
        """If no system-wide configuration and no command-line options are
        specified, the user configuration is used instead."""
        fake_read_system = lambda : {}
        fake_read_user = lambda _: {"electrum_path": self.electrum_dir}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options={},
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

    def test_can_set_options_from_system_config(self):
        fake_read_system = lambda : {"electrum_path": self.electrum_dir}
        fake_read_user = lambda _: {}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options={},
                              read_system_config_function=fake_read_system,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        config.set_key("electrum_path", "c")
        self.assertEqual("c", config.get("electrum_path"))

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

    def test_can_set_options_from_system_config_if_portable(self):
        """If the "portable" flag is set, the user can overwrite system
        configuration options."""
        another_path = tempfile.mkdtemp()
        fake_read_system = lambda : {"electrum_path": self.electrum_dir}
        fake_read_user = lambda _: {}
        read_user_dir = lambda : self.user_dir
        config = SimpleConfig(options={"portable": True},
                              read_system_config_function=fake_read_system,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        config.set_key("electrum_path", another_path)
        self.assertEqual(another_path, config.get("electrum_path"))

    def test_user_config_is_not_written_with_read_only_config(self):
        """The user config does not contain command-line options or system
        options when saved."""
        fake_read_system = lambda : {"something": "b"}
        fake_read_user = lambda _: {"something": "a"}
        read_user_dir = lambda : self.user_dir
        self.options.update({"something": "c"})
        config = SimpleConfig(options=self.options,
                              read_system_config_function=fake_read_system,
                              read_user_config_function=fake_read_user,
                              read_user_dir_function=read_user_dir)
        config.save_user_config()
        contents = None
        with open(os.path.join(self.electrum_dir, "config"), "r") as f:
            contents = f.read()
        result = ast.literal_eval(contents)
        self.assertEqual({"something": "a"}, result)


class TestSystemConfig(unittest.TestCase):

    sample_conf = """
[client]
gap_limit = 5

[something_else]
everything = 42
"""

    def setUp(self):
        super(TestSystemConfig, self).setUp()
        self.thefile = tempfile.mkstemp(suffix=".electrum.test.conf")[1]

    def tearDown(self):
        super(TestSystemConfig, self).tearDown()
        os.remove(self.thefile)

    def test_read_system_config_file_does_not_exist(self):
        somefile = "/foo/I/do/not/exist/electrum.conf"
        result = read_system_config(somefile)
        self.assertEqual({}, result)

    def test_read_system_config_file_returns_file_options(self):
        with open(self.thefile, "w") as f:
            f.write(self.sample_conf)

        result = read_system_config(self.thefile)
        self.assertEqual({"gap_limit": "5"}, result)

    def test_read_system_config_file_no_sections(self):

        with open(self.thefile, "w") as f:
            f.write("gap_limit = 5")  # The file has no sections at all

        result = read_system_config(self.thefile)
        self.assertEqual({}, result)


class TestUserConfig(unittest.TestCase):

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

    def test_path_with_reprd_dict(self):
        thefile = os.path.join(self.user_dir, "config")
        payload = {"gap_limit": 5}
        with open(thefile, "w") as f:
            f.write(json.dumps(payload))

        result = read_user_config(self.user_dir)
        self.assertEqual(payload, result)

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
