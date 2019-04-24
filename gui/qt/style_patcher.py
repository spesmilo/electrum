"""
This is used to patch the QApplication style sheet.
It reads the current stylesheet, appends our modifications and sets the new stylesheet.
"""

from PyQt5 import QtWidgets

def patch(dark: bool = False):
    if not dark:
        return

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
