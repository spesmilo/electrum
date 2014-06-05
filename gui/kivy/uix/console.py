# source: http://stackoverflow.com/questions/2758159/how-to-embed-a-python-interpreter-in-a-pyqt-widget

import sys, os, re
import traceback, platform
from kivy.core.window import Keyboard
from kivy.uix.textinput import TextInput
from kivy.properties import StringProperty, ListProperty, DictProperty
from kivy.clock import Clock

from electrum import util


if platform.system() == 'Windows':
    MONOSPACE_FONT = 'Lucida Console'
elif platform.system() == 'Darwin':
    MONOSPACE_FONT = 'Monaco'
else:
    MONOSPACE_FONT = 'monospace'


class Console(TextInput):

    prompt = StringProperty('>> ')
    '''String representing the Prompt message'''

    startup_message = StringProperty('')
    '''Startup Message to be displayed in the Console if any'''

    history = ListProperty([])
    '''History of the console'''

    namespace = DictProperty({})
    '''Dict representing the current namespace of the console'''

    def __init__(self, **kwargs):
        super(Console, self).__init__(**kwargs)
        self.construct = []
        self.showMessage(self.startup_message)
        self.updateNamespace({'run':self.run_script})
        self.set_json(False)

    def set_json(self, b):
        self.is_json = b

    def run_script(self, filename):
        with open(filename) as f:
            script = f.read()
        result = eval(script, self.namespace, self.namespace)

    def updateNamespace(self, namespace):
        self.namespace.update(namespace)

    def showMessage(self, message):
        self.appendPlainText(message)
        self.newPrompt()

    def clear(self):
        self.setPlainText('')
        self.newPrompt()

    def newPrompt(self):
        if self.construct:
            prompt = '.' * len(self.prompt)
        else:
            prompt = self.prompt

        self.completions_pos = self.cursor_index()
        self.completions_visible = False

        self.appendPlainText(prompt)
        self.move_cursor_to('end')

    def getCommand(self):
        curr_line = self._lines[-1]
        curr_line = curr_line.rstrip()
        curr_line = curr_line[len(self.prompt):]
        return curr_line

    def setCommand(self, command):
        if self.getCommand() == command:
            return
        curr_line = self._lines[-1]
        last_pos = len(self.text)
        self.select_text(last_pos - len(curr_line) + len(self.prompt), last_pos)
        self.delete_selection()
        self.insert_text(command)

    def show_completions(self, completions):
        if self.completions_visible:
            self.hide_completions()

        self.move_cursor_to(self.completions_pos)

        completions = map(lambda x: x.split('.')[-1], completions)
        t = '\n' + ' '.join(completions)
        if len(t) > 500:
            t = t[:500] + '...'
        self.insert_text(t)
        self.completions_end = self.cursor_index()

        self.move_cursor_to('end')
        self.completions_visible = True


    def hide_completions(self):
        if not self.completions_visible:
            return
        self.move_cursor_to(self.completions_pos)
        l = self.completions_end - self.completions_pos
        for x in range(l):
            self.move_cursor_to('cursor_right')
            self.do_backspace()

        self.move_cursor_to('end')
        self.completions_visible = False

    def getConstruct(self, command):
        if self.construct:
            prev_command = self.construct[-1]
            self.construct.append(command)
            if not prev_command and not command:
                ret_val = '\n'.join(self.construct)
                self.construct = []
                return ret_val
            else:
                return ''
        else:
            if command and command[-1] == (':'):
                self.construct.append(command)
                return ''
            else:
                return command

    def getHistory(self):
        return self.history

    def setHisory(self, history):
        self.history = history

    def addToHistory(self, command):
        if command and (not self.history or self.history[-1] != command):
            self.history.append(command)
        self.history_index = len(self.history)

    def getPrevHistoryEntry(self):
        if self.history:
            self.history_index = max(0, self.history_index - 1)
            return self.history[self.history_index]
        return ''

    def getNextHistoryEntry(self):
        if self.history:
            hist_len = len(self.history)
            self.history_index = min(hist_len, self.history_index + 1)
            if self.history_index < hist_len:
                return self.history[self.history_index]
        return ''

    def getCursorPosition(self):
        return self.cursor[0] - len(self.prompt)

    def setCursorPosition(self, position):
        self.cursor = (len(self.prompt) + position, self.cursor[1])

    def register_command(self, c, func):
        methods = { c: func}
        self.updateNamespace(methods)


    def runCommand(self):
        command = self.getCommand()
        self.addToHistory(command)

        command = self.getConstruct(command)

        if command:
            tmp_stdout = sys.stdout

            class stdoutProxy():
                def __init__(self, write_func):
                    self.write_func = write_func
                    self.skip = False

                def flush(self):
                    pass

                def write(self, text):
                    if not self.skip:
                        stripped_text = text.rstrip('\n')
                        self.write_func(stripped_text)
                    self.skip = not self.skip

            if type(self.namespace.get(command)) == type(lambda:None):
                self.appendPlainText("'%s' is a function. Type '%s()' to use it in the Python console."%(command, command))
                self.newPrompt()
                return

            sys.stdout = stdoutProxy(self.appendPlainText)
            try:
                try:
                    result = eval(command, self.namespace, self.namespace)
                    if result != None:
                        if self.is_json:
                            util.print_json(result)
                        else:
                            self.appendPlainText(repr(result))
                except SyntaxError:
                    exec command in self.namespace
            except SystemExit:
                pass
            except:
                traceback_lines = traceback.format_exc().split('\n')
                # Remove traceback mentioning this file, and a linebreak
                for i in (3,2,1,-1):
                    traceback_lines.pop(i)
                self.appendPlainText('\n'.join(traceback_lines))
            sys.stdout = tmp_stdout
        self.newPrompt()
        self.set_json(False)

    def _keyboard_on_key_down(self, window, keycode, text, modifiers):
        self._hide_cut_copy_paste()
        is_osx = sys.platform == 'darwin'
        # Keycodes on OSX:
        ctrl, cmd = 64, 1024
        key, key_str = keycode

        if key == Keyboard.keycodes['tab']:
            self.completions()
            return

        self.hide_completions()

        if key == Keyboard.keycodes['enter']:
            self.runCommand()
            return
        if key == Keyboard.keycodes['home']:
            self.setCursorPosition(0)
            return
        if key == Keyboard.keycodes['pageup']:
            return
        elif key in (Keyboard.keycodes['left'], Keyboard.keycodes['backspace']):
            if self.getCursorPosition() == 0:
                return
        elif key == Keyboard.keycodes['up']:
            self.setCommand(self.getPrevHistoryEntry())
            return
        elif key == Keyboard.keycodes['down']:
            self.setCommand(self.getNextHistoryEntry())
            return
        elif key == Keyboard.keycodes['l'] and modifiers == ['ctrl']:
            self.clear()

        super(Console, self)._keyboard_on_key_down(window, keycode, text, modifiers)

    def completions(self):
        cmd = self.getCommand()
        lastword = re.split(' |\(|\)',cmd)[-1]
        beginning = cmd[0:-len(lastword)]

        path = lastword.split('.')
        ns = self.namespace.keys()

        if len(path) == 1:
            ns = ns
            prefix = ''
        else:
            obj = self.namespace.get(path[0])
            prefix = path[0] + '.'
            ns = dir(obj)


        completions = []
        for x in ns:
            if x[0] == '_':continue
            xx = prefix + x
            if xx.startswith(lastword):
                completions.append(xx)
        completions.sort()

        if not completions:
            self.hide_completions()
        elif len(completions) == 1:
            self.hide_completions()
            self.setCommand(beginning + completions[0])
        else:
            # find common prefix
            p = os.path.commonprefix(completions)
            if len(p)>len(lastword):
                self.hide_completions()
                self.setCommand(beginning + p)
            else:
                self.show_completions(completions)

    # NEW
    def setPlainText(self, message):
        """Equivalent to QT version"""
        self.text = message

    # NEW
    def appendPlainText(self, message):
        """Equivalent to QT version"""
        if len(self.text) == 0:
            self.text = message
        else:
            if message:
                self.text += '\n' + message

    # NEW
    def move_cursor_to(self, pos):
        """Aggregate all cursor moving functions"""
        if isinstance(pos, int):
            self.cursor = self.get_cursor_from_index(pos)
        elif pos in ('end', 'pgend', 'pageend'):
            def updt_cursor(*l):
                self.cursor = self.get_cursor_from_index(self.text)
            Clock.schedule_once(updt_cursor)
        else:  # cursor_home, cursor_end, ... (see docs)
            self.do_cursor_movement(pos)
