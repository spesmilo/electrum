
# source: http://stackoverflow.com/questions/2758159/how-to-embed-a-python-interpreter-in-a-pyqt-widget

import sys
import os
import re
import traceback

from PyQt6 import QtCore
from PyQt6.QtCore import Qt
from PyQt6 import QtGui
from PyQt6 import QtWidgets

from electrum import util
from electrum.i18n import _

from .util import MONOSPACE_FONT, font_height

# sys.ps1 and sys.ps2 are only declared if an interpreter is in interactive mode.
sys.ps1 = '>>> '
sys.ps2 = '... '


class OverlayLabel(QtWidgets.QLabel):
    STYLESHEET = '''
    QLabel, QLabel link {
        color: rgb(0, 0, 0);
        background-color: rgb(248, 240, 200);
        border: 1px solid;
        border-color: rgb(255, 114, 47);
        padding: 2px;
    }
    '''
    def __init__(self, text, parent):
        super().__init__(text, parent)
        self.setMinimumHeight(max(150, 10 * font_height()))
        self.setGeometry(0, 0, self.width(), self.height())
        self.setStyleSheet(self.STYLESHEET)
        self.setMargin(0)
        parent.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setWordWrap(True)

    def mousePressEvent(self, e):
        self.hide()

    def on_resize(self, w):
        padding = 2  # px, from the stylesheet above
        self.setFixedWidth(w - padding)


class Console(QtWidgets.QPlainTextEdit):
    def __init__(self, parent=None):
        QtWidgets.QPlainTextEdit.__init__(self, parent)

        self.history = []
        self.namespace = {}
        self.construct = []

        self.setGeometry(50, 75, 600, 400)
        self.setWordWrapMode(QtGui.QTextOption.WrapMode.WrapAnywhere)
        self.setUndoRedoEnabled(False)
        self.setFont(QtGui.QFont(MONOSPACE_FONT, 10, QtGui.QFont.Weight.Normal))
        self.newPrompt("")  # make sure there is always a prompt, even before first server.banner

        self.updateNamespace({'run':self.run_script})
        self.set_json(False)

        warning_text = "<h1>{}</h1><br>{}<br><br>{}".format(
            _("Warning!"),
            _("Do not paste code here that you don't understand. Executing the wrong code could lead "
              "to your coins being irreversibly lost."),
            _("Click here to hide this message.")
        )
        self.messageOverlay = OverlayLabel(warning_text, self)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        vertical_scrollbar_width = self.verticalScrollBar().width() * self.verticalScrollBar().isVisible()
        self.messageOverlay.on_resize(self.width() - vertical_scrollbar_width)

    def set_json(self, b):
        self.is_json = b

    def run_script(self, filename):
        with open(filename) as f:
            script = f.read()

        self.exec_command(script)

    def updateNamespace(self, namespace):
        self.namespace.update(namespace)

    def showMessage(self, message):
        curr_line = self.getCommand(strip=False)
        self.appendPlainText(message)
        self.newPrompt(curr_line)

    def clear(self):
        curr_line = self.getCommand()
        self.setPlainText('')
        self.newPrompt(curr_line)

    def keyboard_interrupt(self):
        self.construct = []
        self.appendPlainText('KeyboardInterrupt')
        self.newPrompt('')

    def newPrompt(self, curr_line):
        if self.construct:
            prompt = sys.ps2 + curr_line
        else:
            prompt = sys.ps1 + curr_line

        self.completions_pos = self.textCursor().position()
        self.completions_visible = False

        self.appendPlainText(prompt)
        self.moveCursor(QtGui.QTextCursor.MoveOperation.End)

    def getCommand(self, *, strip=True):
        doc = self.document()
        curr_line = doc.findBlockByLineNumber(doc.lineCount() - 1).text()
        if strip:
            curr_line = curr_line.rstrip()
        curr_line = curr_line[len(sys.ps1):]
        return curr_line

    def setCommand(self, command):
        if self.getCommand() == command:
            return

        doc = self.document()
        curr_line = doc.findBlockByLineNumber(doc.lineCount() - 1).text()
        self.moveCursor(QtGui.QTextCursor.MoveOperation.End)
        for i in range(len(curr_line) - len(sys.ps1)):
            self.moveCursor(QtGui.QTextCursor.MoveOperation.Left, QtGui.QTextCursor.MoveMode.KeepAnchor)

        self.textCursor().removeSelectedText()
        self.textCursor().insertText(command)
        self.moveCursor(QtGui.QTextCursor.MoveOperation.End)

    def show_completions(self, completions):
        if self.completions_visible:
            self.hide_completions()

        c = self.textCursor()
        c.setPosition(self.completions_pos)

        completions = map(lambda x: x.split('.')[-1], completions)
        t = '\n' + ' '.join(completions)
        if len(t) > 500:
            t = t[:500] + '...'
        c.insertText(t)
        self.completions_end = c.position()

        self.moveCursor(QtGui.QTextCursor.MoveOperation.End)
        self.completions_visible = True

    def hide_completions(self):
        if not self.completions_visible:
            return
        c = self.textCursor()
        c.setPosition(self.completions_pos)
        l = self.completions_end - self.completions_pos
        for x in range(l): c.deleteChar()

        self.moveCursor(QtGui.QTextCursor.MoveOperation.End)
        self.completions_visible = False

    def getConstruct(self, command):
        if self.construct:
            self.construct.append(command)
            if not command:
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

    def addToHistory(self, command):
        if not self.construct and command[0:1] == ' ':
            return

        if command and (not self.history or self.history[-1] != command):
            while len(self.history) >= 50:
                self.history.remove(self.history[0])
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
        c = self.textCursor()
        return c.position() - c.block().position() - len(sys.ps1)

    def setCursorPosition(self, position):
        self.moveCursor(QtGui.QTextCursor.MoveOperation.StartOfLine)
        for i in range(len(sys.ps1) + position):
            self.moveCursor(QtGui.QTextCursor.MoveOperation.Right)

    def run_command(self):
        command = self.getCommand()
        self.addToHistory(command)

        command = self.getConstruct(command)

        if command:
            self.exec_command(command)
        self.newPrompt('')
        self.set_json(False)

    def exec_command(self, command):
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
                    QtCore.QCoreApplication.processEvents()
                self.skip = not self.skip

        if type(self.namespace.get(command)) == type(lambda:None):
            self.appendPlainText("'{}' is a function. Type '{}()' to use it in the Python console."
                                 .format(command, command))
            return

        sys.stdout = stdoutProxy(self.appendPlainText)
        try:
            try:
                # eval is generally considered bad practice. use it wisely!
                result = eval(command, self.namespace, self.namespace)
                if result is not None:
                    if self.is_json:
                        util.print_msg(util.json_encode(result))
                    else:
                        self.appendPlainText(repr(result))
            except SyntaxError:
                # exec is generally considered bad practice. use it wisely!
                exec(command, self.namespace, self.namespace)
        except SystemExit:
            self.close()
        except BaseException as e:
            te = traceback.TracebackException.from_exception(e)
            # rm part of traceback mentioning this file.
            # (note: we rm stack items before converting to str, instead of removing lines from the str,
            #        as this is more reliable. The latter would differ whether the traceback has source text lines,
            #        which is not always the case.)
            te.stack = traceback.StackSummary.from_list(te.stack[1:])
            tb_str = "".join(te.format())
            # rm last linebreak:
            if tb_str.endswith("\n"):
                tb_str = tb_str[:-1]
            self.appendPlainText(tb_str)
        sys.stdout = tmp_stdout

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Tab:
            self.completions()
            return

        self.hide_completions()

        if event.key() in (Qt.Key.Key_Enter, Qt.Key.Key_Return):
            self.run_command()
            return
        if event.key() == Qt.Key.Key_Home:
            self.setCursorPosition(0)
            return
        if event.key() == Qt.Key.Key_PageUp:
            return
        elif event.key() in (Qt.Key.Key_Left, Qt.Key.Key_Backspace):
            if self.getCursorPosition() == 0:
                return
        elif event.key() == Qt.Key.Key_Up:
            self.setCommand(self.getPrevHistoryEntry())
            return
        elif event.key() == Qt.Key.Key_Down:
            self.setCommand(self.getNextHistoryEntry())
            return
        elif event.key() == Qt.Key.Key_L and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
            self.clear()
        elif event.key() == Qt.Key.Key_C and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
            if not self.textCursor().selectedText():
                self.keyboard_interrupt()

        super(Console, self).keyPressEvent(event)

    def completions(self):
        cmd = self.getCommand()
        # note for regex: new words start after ' ' or '(' or ')'
        lastword = re.split(r'[ ()]', cmd)[-1]
        beginning = cmd[0:-len(lastword)]

        path = lastword.split('.')
        prefix = '.'.join(path[:-1])
        prefix = (prefix + '.') if prefix else prefix
        ns = self.namespace.keys()

        if len(path) == 1:
            ns = ns
        else:
            assert len(path) > 1
            obj = self.namespace.get(path[0])
            try:
                for attr in path[1:-1]:
                    obj = getattr(obj, attr)
            except AttributeError:
                ns = []
            else:
                ns = dir(obj)

        completions = []
        for name in ns:
            if name[0] == '_':continue
            if name.startswith(path[-1]):
                completions.append(prefix+name)
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
