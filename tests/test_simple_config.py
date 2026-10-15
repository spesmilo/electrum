import ast
import sys
import os
import tempfile
import shutil
from io import StringIO

from electrum.simple_config import SimpleConfig, read_user_config

from . import ElectrumTestCase


MAX_MSG_SIZE_DEFAULT = SimpleConfig.NETWORK_MAX_INCOMING_MSG_SIZE.get_default_value()
assert isinstance(MAX_MSG_SIZE_DEFAULT, int), MAX_MSG_SIZE_DEFAULT


class Test_SimpleConfig(ElectrumTestCase):

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

    def test_configvars_set_and_get(self):
        config = SimpleConfig(self.options)
        self.assertEqual("server", config.cv.NETWORK_SERVER.key())

        def _set_via_assignment():
            config.NETWORK_SERVER = "example.com:443:s"

        for f in (
            lambda: config.set_key("server", "example.com:443:s"),
            _set_via_assignment,
            lambda: config.cv.NETWORK_SERVER.set("example.com:443:s"),
        ):
            self.assertTrue(config.get("server") is None)
            self.assertTrue(config.NETWORK_SERVER is None)
            self.assertTrue(config.cv.NETWORK_SERVER.get() is None)
            f()
            self.assertEqual("example.com:443:s", config.get("server"))
            self.assertEqual("example.com:443:s", config.NETWORK_SERVER)
            self.assertEqual("example.com:443:s", config.cv.NETWORK_SERVER.get())
            # revert:
            config.NETWORK_SERVER = None

    def test_configvars_setter_catches_typo(self):
        config = SimpleConfig(self.options)
        assert not hasattr(config, "NETORK_AUTO_CONNECTT")
        with self.assertRaises(AttributeError):
            config.NETORK_AUTO_CONNECTT = False

    def test_configvars_get_default_value(self):
        config = SimpleConfig(self.options)
        self.assertEqual(MAX_MSG_SIZE_DEFAULT, config.cv.NETWORK_MAX_INCOMING_MSG_SIZE.get_default_value())
        self.assertEqual(MAX_MSG_SIZE_DEFAULT, config.NETWORK_MAX_INCOMING_MSG_SIZE)

        config.NETWORK_MAX_INCOMING_MSG_SIZE = 5_555_555
        self.assertEqual(5_555_555, config.NETWORK_MAX_INCOMING_MSG_SIZE)
        self.assertEqual(MAX_MSG_SIZE_DEFAULT, config.cv.NETWORK_MAX_INCOMING_MSG_SIZE.get_default_value())

        config.NETWORK_MAX_INCOMING_MSG_SIZE = None
        self.assertEqual(MAX_MSG_SIZE_DEFAULT, config.NETWORK_MAX_INCOMING_MSG_SIZE)

    def test_configvars_convert_getter(self):
        config = SimpleConfig(self.options)
        self.assertEqual(None, config.NETWORK_PROXY)
        config.user_config[config.cv.NETWORK_PROXY.key()] = None
        self.assertEqual("none", config.NETWORK_PROXY)
        config.NETWORK_PROXY = None
        self.assertEqual(None, config.NETWORK_PROXY)

    def test_configvars_convert_setter(self):
        config = SimpleConfig(self.options)
        self.assertEqual(60, config.CLI_TIMEOUT)
        assert isinstance(config.CLI_TIMEOUT, float)

        config.CLI_TIMEOUT = 10
        self.assertEqual(10, config.CLI_TIMEOUT)
        assert isinstance(config.CLI_TIMEOUT, float)

        config.CLI_TIMEOUT = None
        self.assertEqual(60, config.CLI_TIMEOUT)
        assert isinstance(config.CLI_TIMEOUT, float)

    def test_configvars_is_set(self):
        config = SimpleConfig(self.options)
        self.assertEqual(MAX_MSG_SIZE_DEFAULT, config.NETWORK_MAX_INCOMING_MSG_SIZE)
        self.assertFalse(config.cv.NETWORK_MAX_INCOMING_MSG_SIZE.is_set())

        config.NETWORK_MAX_INCOMING_MSG_SIZE = 5_555_555
        self.assertTrue(config.cv.NETWORK_MAX_INCOMING_MSG_SIZE.is_set())

        config.NETWORK_MAX_INCOMING_MSG_SIZE = None
        self.assertFalse(config.cv.NETWORK_MAX_INCOMING_MSG_SIZE.is_set())
        self.assertEqual(MAX_MSG_SIZE_DEFAULT, config.NETWORK_MAX_INCOMING_MSG_SIZE)

        config.NETWORK_MAX_INCOMING_MSG_SIZE = MAX_MSG_SIZE_DEFAULT
        self.assertTrue(config.cv.NETWORK_MAX_INCOMING_MSG_SIZE.is_set())
        self.assertEqual(MAX_MSG_SIZE_DEFAULT, config.NETWORK_MAX_INCOMING_MSG_SIZE)

    def test_configvars_is_modifiable(self):
        config = SimpleConfig({**self.options, "server": "example.com:443:s"})

        self.assertFalse(config.is_modifiable("server"))
        self.assertFalse(config.cv.NETWORK_SERVER.is_modifiable())

        config.NETWORK_SERVER = "other-example.com:80:t"
        self.assertEqual("example.com:443:s", config.NETWORK_SERVER)

        self.assertEqual(MAX_MSG_SIZE_DEFAULT, config.NETWORK_MAX_INCOMING_MSG_SIZE)
        self.assertTrue(config.cv.NETWORK_MAX_INCOMING_MSG_SIZE.is_modifiable())
        config.NETWORK_MAX_INCOMING_MSG_SIZE = 5_555_555
        self.assertEqual(5_555_555, config.NETWORK_MAX_INCOMING_MSG_SIZE)

        config.make_key_not_modifiable(config.cv.NETWORK_MAX_INCOMING_MSG_SIZE)
        self.assertFalse(config.cv.NETWORK_MAX_INCOMING_MSG_SIZE.is_modifiable())
        config.NETWORK_MAX_INCOMING_MSG_SIZE = 2_222_222
        self.assertEqual(5_555_555, config.NETWORK_MAX_INCOMING_MSG_SIZE)

    def test_configvars_from_key(self):
        config = SimpleConfig(self.options)
        self.assertEqual(config.cv.NETWORK_SERVER, config.cv.from_key("server"))
        with self.assertRaises(KeyError):
            config.cv.from_key("server333")

    def test_recursive_config(self):
        config = SimpleConfig(self.options)
        n = len(config.user_config)
        config.set_key('x.y.z', 1)
        self.assertEqual(len(config.user_config), n + 1)
        config.set_key('x.y.w', 1)
        self.assertEqual(len(config.user_config), n + 1)
        config.set_key('x.y.z', None)
        self.assertEqual(len(config.user_config), n + 1)
        config.set_key('x.y.w', None)
        self.assertEqual(len(config.user_config), n)


class TestUserConfig(ElectrumTestCase):

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

        with self.assertRaises(ValueError):
            read_user_config(self.user_dir)
