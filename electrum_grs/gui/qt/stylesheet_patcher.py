"""This is used to patch the QApplication style sheet.
It reads the current stylesheet, appends our modifications and sets the new stylesheet.
"""

from PyQt5 import QtWidgets


def patch_qt_stylesheet(use_dark_theme: bool) -> None:
    if not use_dark_theme:
        return

    app = QtWidgets.QApplication.instance()

    style_sheet = app.styleSheet()
    style_sheet = style_sheet + '''
    /* PayToEdit text was being clipped */
    QAbstractScrollArea {
        padding: 0px;
    }
    /* In History tab, labels while edited were being clipped (Windows) */
    QAbstractItemView QLineEdit {
        padding: 0px;
        show-decoration-selected: 1;
    }
    /* Checked item in dropdowns have way too much height...
       see #6281 and https://github.com/ColinDuquesnoy/QDarkStyleSheet/issues/200
       */
    QComboBox::item:checked {
        font-weight: bold;
        max-height: 30px;
    }
    '''
    app.setStyleSheet(style_sheet)
