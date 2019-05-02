"""
This is used to patch the QApplication style sheet.
It reads the current stylesheet, appends our modifications and sets the new stylesheet.
"""

from PyQt5 import QtWidgets
from electroncash.util import print_error

def patch(dark: bool = False, darkstyle_ver: tuple = None):
    if not dark:
        return

    if darkstyle_ver is None or darkstyle_ver < (2,6,8):
        # only apply patch to qdarkstyle < 2.6.8.
        # 2.6.8 and above seem to not need it.
        app = QtWidgets.QApplication.instance()

        style_sheet = app.styleSheet()
        style_sheet = style_sheet + '''
        QWidget:disabled {
            color: hsl(0, 0, 50%);
        }
        QPushButton:disabled {
            border-color: hsl(0, 0, 50%);
            color: hsl(0, 0, 50%);
        }
        '''
        app.setStyleSheet(style_sheet)
        print_error("[style_patcher] qdarkstyle < 2.6.8 detected; stylesheet patched")
