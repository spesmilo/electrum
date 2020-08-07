
# source: http://stackoverflow.com/questions/2758159/how-to-embed-a-python-interpreter-in-a-pyqt-widget

import sys
import os
import re
import traceback
import platform

from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5 import QtWidgets

from electroncash import util, get_config
from electroncash.i18n import _
from .util import ColorScheme, MONOSPACE_FONT


class ConsoleWarningOverlay(QtWidgets.QWidget):
    STYLESHEET = '''
    QLabel, QLabel link {
        color: rgb(0, 64, 0);
        background-color: rgba(200, 220, 200, 215);
        border-color: rgba(16, 120, 16, 215);
    }
    '''

    STYLESHEET_DARK = '''
    QLabel, QLabel link {
        color: rgb(180, 220, 180);
        background-color: rgba(3, 12, 3, 215);
        border-color: rgba(3, 96, 3, 215);
    }
    '''

    STYLESHEET_COMMON = '''
    QLabel, QLabel link {
        border: 2px solid;
        padding: 8px;
        font: 12pt;
    }
    '''

    BORDER_RADIUS = 16
    STYLESHEET_BORDER_RADIUS = '''
    QLabel, QLabel link {{
        border-radius: {0}px;
    }}
    '''.format(BORDER_RADIUS)

    CONFIRM_TEXT = _("I UNDERSTAND THE RISK").upper()

    acknowledged = QtCore.pyqtSignal(bool)

    def __init__(self, parent):
        super().__init__(parent)

        util.finalization_print_error(self)

        warning_fmt = '<h1 align="center">{0}</h1><p align=center>{1} {2}<br/><a href="{3}" {5}>{3}</a><p align="center"><font size=+1>{4}</font></p>'
        warning_text = warning_fmt.format(
            _('WARNING'),
            _('Do not enter code here that you don\'t understand. Executing the wrong code could '
              'lead to your coins being irreversibly lost.'),
            _("If someone you do not trust wants you to enter something here, that person might "
              "be attempting a social engineering / phishing attack on you."),
            'https://en.wikipedia.org/wiki/Social_engineering_(security)',
            _("Type: '{}' below to proceed").format('<b>' + self.CONFIRM_TEXT + '</b>'),
            'style="color: #3399ff;"' if ColorScheme.dark_scheme else '',
        )

        style_sheet = self.STYLESHEET_DARK if ColorScheme.dark_scheme else self.STYLESHEET
        style_sheet = style_sheet + self.STYLESHEET_COMMON
        style_sheet = style_sheet + self.STYLESHEET_BORDER_RADIUS
        self.setStyleSheet(style_sheet)

        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(25,25,25,25)
        self.setLayout(layout)

        warning_label = QtWidgets.QLabel(warning_text)
        warning_label.setSizePolicy(QtWidgets.QSizePolicy.Expanding,
                                    QtWidgets.QSizePolicy.MinimumExpanding)
        warning_label.setWordWrap(True)
        warning_label.setOpenExternalLinks(True)
        layoutLbl = QtWidgets.QVBoxLayout()
        layoutLbl.addWidget(warning_label)
        layout.addLayout(layoutLbl, 1)

        if not ColorScheme.dark_scheme:
            drop_shadow_effect = QtWidgets.QGraphicsDropShadowEffect()
            drop_shadow_effect.setBlurRadius(5.0)
            drop_shadow_effect.setOffset(2.0, 2.0)
            drop_shadow_effect.setColor(QtGui.QColor(63,63,63,100))
            warning_label.setGraphicsEffect(drop_shadow_effect)

        hbox_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(hbox_layout)

        fixed = QtWidgets.QSizePolicy.Fixed
        hbox_layout.addSpacerItem(QtWidgets.QSpacerItem(self.BORDER_RADIUS, 0, fixed, fixed))

        self.input_edit = QtWidgets.QLineEdit()
        self.input_edit.textChanged.connect(self.on_text_changed)
        self.input_edit.returnPressed.connect(self.on_confirm)
        hbox_layout.addWidget(self.input_edit)

        self.confirm_btn = QtWidgets.QPushButton(_("&Confirm"))
        self.confirm_btn.setEnabled(False)
        self.confirm_btn.clicked.connect(self.on_confirm)
        hbox_layout.addWidget(self.confirm_btn)

        self.dontaskagain_cbx = QtWidgets.QCheckBox(_("&Don't ask again"))
        hbox_layout.addWidget(self.dontaskagain_cbx)

        hbox_layout.addSpacerItem(QtWidgets.QSpacerItem(self.BORDER_RADIUS, 0, fixed, fixed))

    def input_ok(self) -> bool:
        """
        Returns true if the value in the text input field matches the confirmation text
        """
        return self.input_edit.text().strip().upper() == self.CONFIRM_TEXT

    @QtCore.pyqtSlot()
    def on_text_changed(self):
        """
        Enables the confirm button when the input text matches
        """
        self.confirm_btn.setEnabled(self.input_ok())

    @QtCore.pyqtSlot()
    def on_confirm(self):
        """
        Closes the dialog if the input text matches
        """
        if not self.input_ok():
            return

        self.hide()
        self.acknowledged.emit(self.dontaskagain_cbx.isChecked())

class ConsoleTextEdit(QtWidgets.QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)

    def keyPressEvent(self, event: QtGui.QKeyEvent):
        # Let the warning overlay process key presses when active
        if self.parent().warningOverlay:
            self.parent().warningOverlay.keyPressEvent(event)
            return

        if event.key() == QtCore.Qt.Key_Tab or event.key() == QtCore.Qt.Key_Backtab:
            if (event.modifiers() & QtCore.Qt.ControlModifier) == QtCore.Qt.ControlModifier:
                # Ctrl + Tab / Ctrl + Shift + Tab for navigating the tab control, just let the parent handle it
                pass
            elif (event.modifiers() & QtCore.Qt.ShiftModifier) == QtCore.Qt.ShiftModifier:
                # Shift + Tab, give focus to previous widget
                self.parent().focusPreviousChild()
                return
            else:
                # No Ctrl / Shift pressed, show completions
                self.parent().completions()
                return

        closed_completions = self.parent().hide_completions()

        if event.key() in (QtCore.Qt.Key_Enter, QtCore.Qt.Key_Return):
            self.parent().runCommand()
            return
        if event.key() == QtCore.Qt.Key_Home:
            self.parent().setCursorPosition(0)
            return
        if event.key() == QtCore.Qt.Key_PageUp:
            return
        elif event.key() in (QtCore.Qt.Key_Left, QtCore.Qt.Key_Backspace):
            if self.parent().getCursorPosition() == 0:
                return
        elif event.key() == QtCore.Qt.Key_Up:
            self.parent().setCommand(self.parent().getPrevHistoryEntry())
            return
        elif event.key() == QtCore.Qt.Key_Down:
            self.parent().setCommand(self.parent().getNextHistoryEntry())
            return
        elif event.key() == QtCore.Qt.Key_L and event.modifiers() == QtCore.Qt.ControlModifier:
            self.parent().clear()
        elif event.key() == QtCore.Qt.Key_Insert and event.modifiers() == QtCore.Qt.NoModifier:
            self.setOverwriteMode(not self.overwriteMode())

        super(ConsoleTextEdit, self).keyPressEvent(event)

class Console(QtWidgets.QWidget):
    CONFIG_DONTASKAGAIN_KEY = 'console_warning_dontaskagain'

    def __init__(self, wallet, prompt='>> ', startup_message='', parent=None):
        super().__init__(parent)

        self.prompt = prompt
        self.history = []
        self.namespace = {}
        self.construct = []

        self.setGeometry(50, 75, 600, 400)

        self.editor = ConsoleTextEdit(self)
        self.editor.resize(self.size())
        self.editor.setWordWrapMode(QtGui.QTextOption.WrapAnywhere)
        self.editor.setUndoRedoEnabled(False)
        self.editor.setFont(QtGui.QFont(MONOSPACE_FONT, 10, QtGui.QFont.Normal))

        self.showMessage(startup_message)

        self.updateNamespace({'run':self.run_script})
        self.set_json(False)

        self.warningOverlay = None

        wallet_storage = wallet.storage
        config_dontaskagain = wallet_storage.get(self.CONFIG_DONTASKAGAIN_KEY, False)

        # Don't show the warning if the user chose to have it not shown again
        if not config_dontaskagain:
            self.warningOverlay = ConsoleWarningOverlay(self)
            self.warningOverlay.resize(self.size())

            fp = self.editor.focusPolicy()
            blur_effect = QtWidgets.QGraphicsBlurEffect()
            blur_effect.setBlurRadius(5)
            self.editor.setGraphicsEffect(blur_effect)
            self.editor.setFocusPolicy(QtCore.Qt.NoFocus)
            self.editor.setFocusProxy(self.warningOverlay)
            def on_acknowledged(dontaskagain: bool):
                wallet_storage.put(self.CONFIG_DONTASKAGAIN_KEY, dontaskagain or None)  # None deletes the key
                self.editor.setGraphicsEffect(None)
                self.editor.setFocusPolicy(fp)
                self.editor.setFocusProxy(None)
                # Focus the editor after confirming
                self.editor.setFocus()
                self.warningOverlay.deleteLater()
                self.warningOverlay = None
            self.warningOverlay.acknowledged.connect(on_acknowledged)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self.editor.resize(self.size())
        if self.warningOverlay:
            self.warningOverlay.resize(self.size())

    def set_json(self, b):
        self.is_json = b

    def run_script(self, filename):
        with open(filename, encoding='utf-8') as f:
            script = f.read()

        # eval is generally considered bad practice. use it wisely!
        result = eval(script, self.namespace, self.namespace)

    def updateNamespace(self, namespace):
        self.namespace.update(namespace)

    def showMessage(self, message):
        self.editor.appendPlainText(message)
        self.newPrompt()

    def clear(self):
        self.editor.setPlainText('')
        self.newPrompt()

    def newPrompt(self):
        if self.construct:
            prompt = '.' * len(self.prompt)
        else:
            prompt = self.prompt

        self.completions_pos = self.editor.textCursor().position()
        self.completions_visible = False

        self.editor.appendPlainText(prompt)
        self.editor.moveCursor(QtGui.QTextCursor.End)

    def getCommand(self):
        doc = self.editor.document()
        curr_line = doc.findBlockByLineNumber(doc.lineCount() - 1).text()
        curr_line = curr_line.rstrip()
        curr_line = curr_line[len(self.prompt):]
        return curr_line

    def setCommand(self, command):
        if self.getCommand() == command:
            return

        doc = self.editor.document()
        curr_line = doc.findBlockByLineNumber(doc.lineCount() - 1).text()
        self.editor.moveCursor(QtGui.QTextCursor.End)
        for i in range(len(curr_line) - len(self.prompt)):
            self.editor.moveCursor(QtGui.QTextCursor.Left, QtGui.QTextCursor.KeepAnchor)

        self.editor.textCursor().removeSelectedText()
        self.editor.textCursor().insertText(command)
        self.editor.moveCursor(QtGui.QTextCursor.End)

    def show_completions(self, completions):
        if self.completions_visible:
            self.hide_completions()

        c = self.editor.textCursor()
        c.setPosition(self.completions_pos)

        completions = map(lambda x: x.split('.')[-1], completions)
        t = '\n' + ' '.join(completions)
        if len(t) > 500:
            t = t[:500] + '...'
        c.insertText(t)
        self.completions_end = c.position()

        self.editor.moveCursor(QtGui.QTextCursor.End)
        self.completions_visible = True

    def hide_completions(self) -> bool:
        if not self.completions_visible:
            return False
        c = self.editor.textCursor()
        c.setPosition(self.completions_pos)
        l = self.completions_end - self.completions_pos
        for x in range(l): c.deleteChar()

        self.editor.moveCursor(QtGui.QTextCursor.End)
        self.completions_visible = False
        return True

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

    def addToHistory(self, command):
        if command[0:1] == ' ':
            return

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
        c = self.editor.textCursor()
        return c.position() - c.block().position() - len(self.prompt)

    def setCursorPosition(self, position):
        self.editor.moveCursor(QtGui.QTextCursor.StartOfLine)
        for i in range(len(self.prompt) + position):
            self.editor.moveCursor(QtGui.QTextCursor.Right)

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
                        QtCore.QCoreApplication.processEvents()
                    self.skip = not self.skip

            if type(self.namespace.get(command)) == type(lambda:None):
                self.editor.appendPlainText("'{}' is a function. Type '{}()' to use it in the Python console."
                                     .format(command, command))
                self.newPrompt()
                return

            sys.stdout = stdoutProxy(self.editor.appendPlainText)
            try:
                try:
                    # eval is generally considered bad practice. use it wisely!
                    result = eval(command, self.namespace, self.namespace)
                    if result is not None:
                        if self.is_json:
                            util.print_msg(util.json_encode(result))
                        else:
                            self.editor.appendPlainText(repr(result))
                except SyntaxError:
                    # exec is generally considered bad practice. use it wisely!
                    exec(command, self.namespace, self.namespace)
            except SystemExit:
                self.close()
            except (Exception, BaseException):
                # Catch errors in the network layer as well, as long as it uses BaseException.
                traceback_lines = traceback.format_exc().split('\n')
                # Remove traceback mentioning this file, and a linebreak
                for i in (3,2,1,-1):
                    traceback_lines.pop(i)
                self.editor.appendPlainText('\n'.join(traceback_lines))
            sys.stdout = tmp_stdout
        self.newPrompt()
        self.set_json(False)

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


welcome_message = '''
   ---------------------------------------------------------------
     Welcome to a primitive Python interpreter.
   ---------------------------------------------------------------
'''

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    console = Console(startup_message=welcome_message)
    console.updateNamespace({'myVar1' : app, 'myVar2' : 1234})
    console.show()
    sys.exit(app.exec_())
