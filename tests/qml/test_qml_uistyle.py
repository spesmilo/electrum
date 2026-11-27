"""The style switch of the QML GUI (Material 3 or classic) and the fallback when Material 3 fails to start.

Covers QEConfig.uiStyle / QEConfig.m3Theme (read, write to memory and to disk, change signal), the defaults of a
new config (qml_ui_style, qml_m3_theme), the paths of the two main.qml files and ElectrumGui._load_main_qml, called
on a fake GUI object with the real paths of the class (no window, no QGuiApplication). "On disk" is what a new
SimpleConfig over the same directory reads, as the next start of the app does. The expected values are literals of
the documented behaviour, never read back from the code under test.
"""
import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace

from electrum import SimpleConfig
from electrum.logging import get_logger
from electrum.gui.qml import ElectrumGui
from electrum.gui.qml.qeconfig import QEConfig

from .qt_util import QETestCase, QEventReceiver, qt_test


CLASSIC = 'electrum/gui/qml/components/main.qml'
MATERIAL3 = 'electrum/gui/qml/components_m3/main.qml'


class TestUiStyleConfig(QETestCase):
    """QEConfig.uiStyle and QEConfig.m3Theme over a real SimpleConfig."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._base = tempfile.mkdtemp(prefix="electrum-unittest-base-")
        cls._config = SimpleConfig({'electrum_path': os.path.join(cls._base, "electrum")})
        # QEConfig is a singleton (QEConfig.__init__ refuses a second one): the one another test module may have
        # made is put aside and given back afterwards
        cls._saved_instance = QEConfig.instance

    @classmethod
    def tearDownClass(cls) -> None:
        QEConfig.instance = cls._saved_instance
        shutil.rmtree(cls._base)
        super().tearDownClass()

    def tearDown(self):
        self.q = None
        QEConfig.instance = None
        super().tearDown()

    def _make_q(self) -> QEConfig:
        # made in the Qt thread of this test (each test runs its own QCoreApplication)
        QEConfig.instance = None
        self.q = QEConfig(self._config)
        return self.q

    @qt_test
    def test_ui_style_reads_the_config(self):
        self._make_q()
        self.q.config.GUI_QML_UI_STYLE = 'classic'
        self.assertEqual(self.q.uiStyle, 'classic')
        self.q.config.GUI_QML_UI_STYLE = 'material3-failed'
        self.assertEqual(self.q.uiStyle, 'material3-failed')

    @qt_test
    def test_ui_style_write_changes_the_config_and_signals_once(self):
        self._make_q()
        self.q.config.GUI_QML_UI_STYLE = 'material3'
        receiver = QEventReceiver(self.q.uiStyleChanged)
        self.q.uiStyle = 'classic'
        self.assertEqual(self.q.config.GUI_QML_UI_STYLE, 'classic')
        self.assertEqual(len(receiver.receivedForSignal(self.q.uiStyleChanged)), 1)

    @qt_test
    def test_ui_style_write_is_saved_to_disk(self):
        self._make_q()
        self.q.config.GUI_QML_UI_STYLE = 'material3'
        self.q.uiStyle = 'classic'
        again = SimpleConfig({'electrum_path': os.path.join(self._base, "electrum")})
        self.assertEqual(again.get('qml_ui_style'), 'classic')

    @qt_test
    def test_ui_style_same_value_does_not_signal(self):
        self._make_q()
        self.q.config.GUI_QML_UI_STYLE = 'classic'
        receiver = QEventReceiver(self.q.uiStyleChanged)
        self.q.uiStyle = 'classic'
        self.assertEqual(self.q.config.GUI_QML_UI_STYLE, 'classic')
        self.assertEqual(len(receiver.receivedForSignal(self.q.uiStyleChanged)), 0)

    @qt_test
    def test_m3_theme_reads_the_config(self):
        self._make_q()
        self.q.config.GUI_QML_M3_THEME = 'dark'
        self.assertEqual(self.q.m3Theme, 'dark')
        self.q.config.GUI_QML_M3_THEME = 'light'
        self.assertEqual(self.q.m3Theme, 'light')

    @qt_test
    def test_m3_theme_write_changes_the_config_and_signals_once(self):
        self._make_q()
        self.q.config.GUI_QML_M3_THEME = 'system'
        receiver = QEventReceiver(self.q.m3ThemeChanged)
        self.q.m3Theme = 'dark'
        self.assertEqual(self.q.config.GUI_QML_M3_THEME, 'dark')
        self.assertEqual(len(receiver.receivedForSignal(self.q.m3ThemeChanged)), 1)

    @qt_test
    def test_m3_theme_write_is_saved_to_disk(self):
        self._make_q()
        self.q.config.GUI_QML_M3_THEME = 'system'
        self.q.m3Theme = 'dark'
        again = SimpleConfig({'electrum_path': os.path.join(self._base, "electrum")})
        self.assertEqual(again.get('qml_m3_theme'), 'dark')

    @qt_test
    def test_m3_theme_same_value_does_not_signal(self):
        self._make_q()
        self.q.config.GUI_QML_M3_THEME = 'light'
        receiver = QEventReceiver(self.q.m3ThemeChanged)
        self.q.m3Theme = 'light'
        self.assertEqual(self.q.config.GUI_QML_M3_THEME, 'light')
        self.assertEqual(len(receiver.receivedForSignal(self.q.m3ThemeChanged)), 0)


class TestUiStyleDefaults(unittest.TestCase):
    """A new config (no key written): Material 3 with the theme of the system."""

    def setUp(self):
        super().setUp()
        self._base = tempfile.mkdtemp(prefix="electrum-unittest-base-")
        self.addCleanup(shutil.rmtree, self._base)

    def test_new_config_defaults(self):
        config = SimpleConfig({'electrum_path': os.path.join(self._base, "electrum")})
        self.assertEqual(config.GUI_QML_UI_STYLE, 'material3')
        self.assertEqual(config.GUI_QML_M3_THEME, 'system')
        # nothing was written: the values are the defaults, not stored keys
        self.assertIsNone(config.get('qml_ui_style'))
        self.assertIsNone(config.get('qml_m3_theme'))


class _FakeSignal:
    """engine.objectCreated: connect/disconnect as PyQt6 (disconnecting a slot that is not connected raises
    TypeError)."""

    def __init__(self, connected=()):
        self.slots = list(connected)
        self.disconnects = 0

    def connect(self, slot):
        self.slots.append(slot)

    def disconnect(self, slot):
        self.disconnects += 1
        if slot not in self.slots:
            raise TypeError('disconnect() failed between objectCreated and objectCreated')
        self.slots.remove(slot)


class _FakeEngine:
    """Records each load() with the state seen at that moment; rootObjects() is empty after a load of the paths
    in `fail`."""

    def __init__(self, app, config, fail=()):
        self._app = app
        self._config = config
        self._fail = set(fail)
        self._roots = []
        self.loads = []
        self.objectCreated = None  # set by _FakeApp

    def load(self, path):
        self.loads.append({
            'path': path,
            'ui_style': self._config.GUI_QML_UI_STYLE,
            'valid': self._app._valid,
            'slots': list(self.objectCreated.slots),
        })
        self._roots = [] if path in self._fail else [object()]

    def rootObjects(self):
        return list(self._roots)


class _FakeApp:
    def __init__(self, config, fail=(), slot_connected=True):
        self._valid = False
        self.engine = _FakeEngine(self, config, fail)
        self.engine.objectCreated = _FakeSignal([self.objectCreated] if slot_connected else [])

    def objectCreated(self, obj, url):  # stands for ElectrumQmlApplication.objectCreated
        pass


class TestLoadMainQml(unittest.TestCase):
    """ElectrumGui._load_main_qml on a fake GUI object: which main.qml is loaded, and the fallback. The fake object
    carries the paths of the class (ElectrumGui.CLASSIC_MAIN_QML / M3_MAIN_QML); the cells compare the loads with the
    literals CLASSIC / MATERIAL3."""

    def setUp(self):
        super().setUp()
        self._base = tempfile.mkdtemp(prefix="electrum-unittest-base-")
        self.addCleanup(shutil.rmtree, self._base)
        self.config = SimpleConfig({'electrum_path': os.path.join(self._base, "electrum")})

    def _gui(self, ui_style, fail=(), slot_connected=True):
        if ui_style is not None:
            self.config.GUI_QML_UI_STYLE = ui_style
        app = _FakeApp(self.config, fail=fail, slot_connected=slot_connected)
        gui = SimpleNamespace(
            config=self.config,
            logger=get_logger('test_qml_uistyle'),
            app=app,
            CLASSIC_MAIN_QML=ElectrumGui.CLASSIC_MAIN_QML,
            M3_MAIN_QML=ElectrumGui.M3_MAIN_QML,
        )
        return gui, app

    def test_main_qml_paths(self):
        # which file is which set: components/ is the classic GUI, components_m3/ is Material 3
        self.assertEqual(ElectrumGui.CLASSIC_MAIN_QML, CLASSIC)
        self.assertEqual(ElectrumGui.M3_MAIN_QML, MATERIAL3)

    def test_classic_loads_only_classic(self):
        gui, app = self._gui('classic')
        ElectrumGui._load_main_qml(gui)
        self.assertEqual([x['path'] for x in app.engine.loads], [CLASSIC])
        self.assertEqual(self.config.GUI_QML_UI_STYLE, 'classic')
        self.assertFalse(app._valid)

    def test_other_values_load_classic_and_keep_the_config(self):
        for value in ('material3-failed', 'foo'):
            with self.subTest(value=value):
                gui, app = self._gui(value)
                ElectrumGui._load_main_qml(gui)
                self.assertEqual([x['path'] for x in app.engine.loads], [CLASSIC])
                self.assertEqual(self.config.GUI_QML_UI_STYLE, value)
                self.assertFalse(app._valid)

    def test_material3_loads_only_material3(self):
        gui, app = self._gui('material3')
        ElectrumGui._load_main_qml(gui)
        self.assertEqual([x['path'] for x in app.engine.loads], [MATERIAL3])
        self.assertEqual(self.config.GUI_QML_UI_STYLE, 'material3')
        self.assertFalse(app._valid)
        self.assertEqual(app.engine.objectCreated.disconnects, 0)

    def test_default_config_loads_material3(self):
        gui, app = self._gui(None)
        ElectrumGui._load_main_qml(gui)
        self.assertEqual([x['path'] for x in app.engine.loads], [MATERIAL3])

    def test_material3_failure_falls_back_to_classic(self):
        gui, app = self._gui('material3', fail=(MATERIAL3,))
        ElectrumGui._load_main_qml(gui)
        loads = app.engine.loads
        self.assertEqual([x['path'] for x in loads], [MATERIAL3, CLASSIC])
        self.assertEqual(self.config.GUI_QML_UI_STYLE, 'material3-failed')
        self.assertEqual(self.config.get('qml_ui_style'), 'material3-failed')
        self.assertTrue(app._valid)
        # before the classic load: the style is persisted, the app is valid again, and objectCreated is
        # connected exactly once to the app's handler
        self.assertEqual(loads[1]['ui_style'], 'material3-failed')
        self.assertTrue(loads[1]['valid'])
        self.assertEqual(loads[1]['slots'], [app.objectCreated])
        self.assertEqual(app.engine.objectCreated.disconnects, 1)

    def test_material3_failure_is_saved_to_disk(self):
        gui, app = self._gui('material3', fail=(MATERIAL3,))
        ElectrumGui._load_main_qml(gui)
        again = SimpleConfig({'electrum_path': os.path.join(self._base, "electrum")})
        self.assertEqual(again.get('qml_ui_style'), 'material3-failed')

    def test_material3_failure_with_the_handler_already_disconnected(self):
        # ElectrumQmlApplication.objectCreated disconnects itself after its first call: the TypeError of the
        # disconnect is swallowed and the handler is connected once
        gui, app = self._gui('material3', fail=(MATERIAL3,), slot_connected=False)
        ElectrumGui._load_main_qml(gui)
        loads = app.engine.loads
        self.assertEqual([x['path'] for x in loads], [MATERIAL3, CLASSIC])
        self.assertEqual(self.config.GUI_QML_UI_STYLE, 'material3-failed')
        self.assertTrue(app._valid)
        self.assertEqual(loads[1]['slots'], [app.objectCreated])
        self.assertEqual(app.engine.objectCreated.disconnects, 1)
