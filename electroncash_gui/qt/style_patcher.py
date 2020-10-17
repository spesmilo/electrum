"""
This is used to patch the QApplication style sheet.
It reads the current stylesheet, appends our modifications and sets the new stylesheet.
"""

from PyQt5 import QtWidgets
from electroncash.util import print_error

def patch(dark: bool = False, darkstyle_ver: tuple = None):
    if not dark:
        return

    app = QtWidgets.QApplication.instance()

    if darkstyle_ver is None or darkstyle_ver < (2,6,8):
        # only apply this patch to qdarkstyle < 2.6.8.
        # 2.6.8 and above seem to not need it.

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
        print_error("[style_patcher] qdarkstyle < 2.6.8 detected; stylesheet patch #1 applied")
    else:
        # This patch is for qdarkstyle >= 2.6.8.

        style_sheet = app.styleSheet()
        style_sheet = style_sheet + '''
        /* PayToEdit was being cut off on QDatkStyle >= 2.6.8. This fixes that. */
        ButtonsTextEdit {
            padding: 0px;
        }
        /* History List labels, when editing, were looking terrible in Windows and were cut off. This fixes that.*/
        QTreeWidget QLineEdit {
            show-decoration-selected: 1;
            padding: 0px;
        }
        '''
        app.setStyleSheet(style_sheet)
        print_error("[style_patcher] qdarkstyle >= 2.6.8 detected; stylesheet patch #2 applied")
