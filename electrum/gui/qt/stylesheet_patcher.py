"""This is used to patch the QApplication style sheet.
It reads the current stylesheet, appends our modifications and sets the new stylesheet.
"""

import sys

from PyQt5 import QtWidgets


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

/* On macOS, checkable QMenu items do not draw empty checkboxes, and so they cannot be distinguished from buttons.
See #8288. The below customises the whole of QMenu, as a workaround, taken from the qdarkstyle "light" theme.
from https://github.com/ColinDuquesnoy/QDarkStyleSheet/blob/6ff5fdfd7b1e2a538b6f22bd85dd05a817d24c45/qdarkstyle/light/lightstyle.qss#L388
*/
QMenu {
  border: 0px solid #C9CDD0;
  color: #19232D;
  margin: 0px;
  background-color: #CED1D4;
  selection-background-color: #73C7FF;
}
QMenu::separator {
  height: 1px;
  background-color: #ACB1B6;
  color: #19232D;
}
QMenu::item {
  background-color: #CED1D4;
  padding: 4px 24px 4px 28px;
  /* Reserve space for selection border */
  border: 1px transparent #C9CDD0;
}
QMenu::item:selected {
  color: #19232D;
  background-color: #73C7FF;
}
QMenu::item:pressed {
  background-color: #73C7FF;
}
QMenu::icon {
  padding-left: 10px;
  width: 14px;
  height: 14px;
}
QMenu::indicator {
  padding-left: 8px;
  width: 12px;
  height: 12px;
  /* non-exclusive indicator = check box style indicator (see QActionGroup::setExclusive) */
  /* exclusive indicator = radio button style indicator (see QActionGroup::setExclusive) */
}
QMenu::indicator:non-exclusive:unchecked {
  image: url("qdarkstyle_light:checkbox_unchecked.png");
}
QMenu::indicator:non-exclusive:unchecked:hover, QMenu::indicator:non-exclusive:unchecked:focus, QMenu::indicator:non-exclusive:unchecked:pressed {
  border: none;
  image: url("qdarkstyle_light:checkbox_unchecked_focus.png");
}
QMenu::indicator:non-exclusive:unchecked:disabled {
  image: url("qdarkstyle_light:checkbox_unchecked_disabled.png");
}
QMenu::indicator:non-exclusive:checked {
  image: url("qdarkstyle_light:checkbox_checked.png");
}
QMenu::indicator:non-exclusive:checked:hover, QMenu::indicator:non-exclusive:checked:focus, QMenu::indicator:non-exclusive:checked:pressed {
  border: none;
  image: url("qdarkstyle_light:checkbox_checked_focus.png");
}
QMenu::indicator:non-exclusive:checked:disabled {
  image: url("qdarkstyle_light:checkbox_checked_disabled.png");
}
QMenu::indicator:non-exclusive:indeterminate {
  image: url("qdarkstyle_light:checkbox_indeterminate.png");
}
QMenu::indicator:non-exclusive:indeterminate:disabled {
  image: url("qdarkstyle_light:checkbox_indeterminate_disabled.png");
}
QMenu::indicator:non-exclusive:indeterminate:focus, QMenu::indicator:non-exclusive:indeterminate:hover, QMenu::indicator:non-exclusive:indeterminate:pressed {
  image: url("qdarkstyle_light:checkbox_indeterminate_focus.png");
}
QMenu::indicator:exclusive:unchecked {
  image: url("qdarkstyle_light:radio_unchecked.png");
}
QMenu::indicator:exclusive:unchecked:hover, QMenu::indicator:exclusive:unchecked:focus, QMenu::indicator:exclusive:unchecked:pressed {
  border: none;
  outline: none;
  image: url("qdarkstyle_light:radio_unchecked_focus.png");
}
QMenu::indicator:exclusive:unchecked:disabled {
  image: url("qdarkstyle_light:radio_unchecked_disabled.png");
}
QMenu::indicator:exclusive:checked {
  border: none;
  outline: none;
  image: url("qdarkstyle_light:radio_checked.png");
}
QMenu::indicator:exclusive:checked:hover, QMenu::indicator:exclusive:checked:focus, QMenu::indicator:exclusive:checked:pressed {
  border: none;
  outline: none;
  image: url("qdarkstyle_light:radio_checked_focus.png");
}
QMenu::indicator:exclusive:checked:disabled {
  outline: none;
  image: url("qdarkstyle_light:radio_checked_disabled.png");
}
QMenu::right-arrow {
  margin: 5px;
  padding-left: 12px;
  image: url("qdarkstyle_light:arrow_right.png");
  height: 12px;
  width: 12px;
}
/* patch from https://github.com/ColinDuquesnoy/QDarkStyleSheet/blob/6ff5fdfd7b1e2a538b6f22bd85dd05a817d24c45/qdarkstyle/__init__.py#L164 */
QMenu::item {
  padding: 4px 24px 4px 6px;
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
