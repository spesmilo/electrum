"""This is used to patch the QApplication style sheet.
It reads the current stylesheet, appends our modifications and sets the new stylesheet.
"""

import sys

from PyQt6 import QtWidgets


CUSTOM_PATCH_FOR_DARK_THEME = '''
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

CUSTOM_PATCH_FOR_DEFAULT_THEME_MACOS = '''
/* On macOS, main window status bar icons have ugly frame (see #6300) */
StatusBarButton {
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 4px;
    margin: 0px;
    padding: 2px;
}
StatusBarButton:checked {
  background-color: transparent;
  border: 1px solid #1464A0;
}
StatusBarButton:checked:disabled {
  border: 1px solid #14506E;
}
StatusBarButton:pressed {
  margin: 1px;
  background-color: transparent;
  border: 1px solid #1464A0;
}
StatusBarButton:disabled {
  border: none;
}
StatusBarButton:hover {
  border: 1px solid #148CD2;
}
'''


def patch_qt_stylesheet(use_dark_theme: bool) -> None:
    custom_patch = ""
    if use_dark_theme:
        custom_patch = CUSTOM_PATCH_FOR_DARK_THEME
    else:  # default theme (typically light)
        if sys.platform == 'darwin':
            custom_patch = CUSTOM_PATCH_FOR_DEFAULT_THEME_MACOS

    app = QtWidgets.QApplication.instance()
    style_sheet = app.styleSheet() + custom_patch
    app.setStyleSheet(style_sheet)
