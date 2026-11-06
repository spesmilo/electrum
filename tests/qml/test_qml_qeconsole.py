from electrum import SimpleConfig
from electrum.gui.qml.qeconsole import QEConsole

from .qt_util import QETestCase, qt_test


class TestConsole(QETestCase):

    def _console(self):
        return QEConsole(SimpleConfig())

    @qt_test
    def test_eval_expression(self):
        c = self._console()
        c.runCommand('2 + 2')
        self.assertIn('>>> 2 + 2\n', c.output)
        self.assertIn('4\n', c.output)

    @qt_test
    def test_exec_statement_and_namespace_persistence(self):
        c = self._console()
        c.runCommand('x = 5')
        c.runCommand('x * 2')
        self.assertIn('10\n', c.output)

    @qt_test
    def test_print_capture(self):
        c = self._console()
        c.runCommand('print("hello world")')
        self.assertIn('hello world\n', c.output)

    @qt_test
    def test_traceback_shown_and_filtered(self):
        c = self._console()
        c.runCommand('1 / 0')
        self.assertIn('ZeroDivisionError', c.output)
        self.assertNotIn('qeconsole.py', c.output)

    @qt_test
    def test_system_exit_does_not_propagate(self):
        c = self._console()
        c.runCommand('raise SystemExit')  # must not kill the process
        self.assertIn('SystemExit', c.output)

    @qt_test
    def test_bare_function_name_hint(self):
        c = self._console()
        c.runCommand('f = lambda: 1')
        c.runCommand('f')
        self.assertIn("'f' is a function", c.output)
        # note: bound methods (like 'run') intentionally don't trigger the
        # hint -- same behavior as the Qt console, which checks FunctionType

    @qt_test
    def test_output_trimmed(self):
        c = self._console()
        c.runCommand('print("a" * 300000)')
        self.assertLessEqual(len(c.output), QEConsole.MAX_OUTPUT_SIZE)

    @qt_test
    def test_multiline_construct(self):
        c = self._console()
        c.runCommand('for i in range(3):')
        self.assertTrue(c.inConstruct)
        self.assertEqual(c.prompt, '... ')
        c.runCommand('    print(i)')
        self.assertTrue(c.inConstruct)
        c.runCommand('')
        self.assertFalse(c.inConstruct)
        self.assertEqual(c.prompt, '>>> ')
        self.assertIn('0\n1\n2\n', c.output)

    @qt_test
    def test_keyboard_interrupt_aborts_construct(self):
        c = self._console()
        c.runCommand('for i in range(3):')
        self.assertTrue(c.inConstruct)
        c.keyboardInterrupt()
        self.assertFalse(c.inConstruct)
        self.assertIn('KeyboardInterrupt', c.output)
        # construct must not execute afterwards
        c.runCommand('"done"')
        self.assertIn("'done'\n", c.output)

    @qt_test
    def test_history_navigation(self):
        c = self._console()
        c.runCommand('1')
        c.runCommand('2')
        self.assertEqual(c.getPrevHistoryEntry(), '2')
        self.assertEqual(c.getPrevHistoryEntry(), '1')
        self.assertEqual(c.getPrevHistoryEntry(), '1')  # clamps at oldest
        self.assertEqual(c.getNextHistoryEntry(), '2')
        self.assertEqual(c.getNextHistoryEntry(), '')   # past newest

    @qt_test
    def test_history_dedup_and_cap(self):
        c = self._console()
        c.runCommand('1')
        c.runCommand('1')  # consecutive duplicate not recorded
        self.assertEqual(len(c._history), 1)
        for i in range(QEConsole.MAX_HISTORY_SIZE + 10):
            c.runCommand(str(i))
        self.assertEqual(len(c._history), QEConsole.MAX_HISTORY_SIZE)

    @qt_test
    def test_clear(self):
        c = self._console()
        c.runCommand('1')
        c.clear()
        self.assertEqual(c.output, '')

    @qt_test
    def test_completion_single_match(self):
        c = self._console()
        c.runCommand('zebra_value = 42')
        r = c.getCompletions('zebr')
        self.assertEqual(r['text'], 'zebra_value')
        self.assertEqual(r['candidates'], [])

    @qt_test
    def test_completion_common_prefix(self):
        c = self._console()
        c.runCommand('zebra_one = 1')
        c.runCommand('zebra_two = 2')
        r = c.getCompletions('zeb')
        self.assertEqual(r['text'], 'zebra_')
        self.assertEqual(r['candidates'], [])

    @qt_test
    def test_completion_candidates(self):
        c = self._console()
        c.runCommand('zebra_one = 1')
        c.runCommand('zebra_two = 2')
        r = c.getCompletions('zebra_')
        self.assertEqual(r['text'], 'zebra_')
        self.assertEqual(sorted(r['candidates']), ['zebra_one', 'zebra_two'])

    @qt_test
    def test_completion_attribute_path(self):
        c = self._console()
        r = c.getCompletions('util.json_enc')
        self.assertEqual(r['text'], 'util.json_encode')

    @qt_test
    def test_completion_preserves_preceding_text(self):
        c = self._console()
        c.runCommand('zebra_value = 42')
        r = c.getCompletions('print(zebr')
        self.assertEqual(r['text'], 'print(zebra_value')
        self.assertEqual(r['beginning'], 'print(')

    @qt_test
    def test_completion_unknown(self):
        c = self._console()
        r = c.getCompletions('nonexistent_thing_xyz.attr')
        self.assertEqual(r['text'], 'nonexistent_thing_xyz.attr')
        self.assertEqual(r['candidates'], [])

    @qt_test
    def test_commands_in_namespace(self):
        c = self._console()
        # bare command name shows the function hint (commands are wrapped callables)
        c.runCommand('getinfo')
        self.assertIn("'getinfo' is a function", c.output)

    @qt_test
    def test_wallet_in_namespace_without_daemon(self):
        c = self._console()
        c.runCommand('wallet is None')
        self.assertIn('True\n', c.output)

    @qt_test
    def test_user_assigned_wallet_var_persists(self):
        c = self._console()
        # 'wallet' is only re-injected into the namespace when the open
        # wallet changes, so a user assignment must survive other commands
        c.runCommand('wallet = "test"')
        c.runCommand('1 + 1')
        c.runCommand('wallet')
        self.assertIn("'test'\n", c.output)
