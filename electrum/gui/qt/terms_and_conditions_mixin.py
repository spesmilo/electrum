import os
from pathlib import Path

from PyQt5.QtWidgets import QVBoxLayout, QTextEdit, QLabel, QHBoxLayout, QStyle, QPushButton

from electrum.base_wizard import GoBack
from electrum.gui.qt.util import WindowModalDialog
from electrum.i18n import _


class WarningDialog(WindowModalDialog):
    def __init__(self, parent, title=_('Warning')):
        super().__init__(parent=parent, title=title)
        self.second_chance_for_reading = True
        vbox = QVBoxLayout(self)
        warning_box = QHBoxLayout()
        # FIXME new line works only with <br> not \n
        warning_label = QLabel(
            '<b>' + _('Are you sure?') + '</b>' + 1 * '<br>' +
            _("Note that if you disagree to our Terms & Conditions you won't be able to use"
              " the Electrum Vault application.") + 1 * '<br>' +
            _('Are you sure you want to disagree?') + 1 * '<br>'
        )
        warning_label.setMinimumWidth(450)
        warning_label.setWordWrap(True)
        icon_label = QLabel()
        icon = icon_label.style().standardIcon(QStyle.SP_MessageBoxWarning)
        icon_label.setPixmap(icon.pixmap(52, 52))
        warning_box.addWidget(icon_label)
        warning_box.addWidget(warning_label)
        warning_box.addStretch(1)
        vbox.addLayout(warning_box)
        hbox = QHBoxLayout()
        back_button = QPushButton(_('No, I changed my mind'))
        back_button.clicked.connect(lambda: self.close())
        cancel_button = QPushButton(_('Yes, I disagree'))
        cancel_button.clicked.connect(self.cancel)
        cancel_button.setDefault(True)
        hbox.addStretch(1)
        hbox.addWidget(back_button)
        hbox.addWidget(cancel_button)
        vbox.addStretch(1)
        vbox.addLayout(hbox)
        self.exec_()

    def cancel(self):
        self.second_chance_for_reading = False
        self.close()


class TermsAndConditionsTextEdit(QTextEdit):
    def __init__(self, next_button, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.next_button = next_button
        self.setReadOnly(True)
        scroll_bar = self.verticalScrollBar()
        scroll_bar.valueChanged.connect(self.scrolled)
        self._scroll_bar_range_hit_max = False
        scroll_bar.rangeChanged.connect(self.range_changed)

    def _scroll_bar_max_position(self):
        return self.verticalScrollBar().maximum()

    def scrolled(self, scroll_bar_position:int):
        # check if user scrolled to the bottom of the text
        if scroll_bar_position == self._scroll_bar_max_position():
            self.next_button.setEnabled(True)

    def range_changed(self, *range):
        # it is called when window is resized
        if not self._scroll_bar_range_hit_max:
            if range[1]:
                self.next_button.setEnabled(False)
            else:
                self._scroll_bar_range_hit_max = True
                self.next_button.setEnabled(True)


class TermsAndConditionsMixin:
    # TODO change file with lorem ipsum
    def _read_terms_and_conditions(self) -> str:
        dir_ = Path(os.path.abspath(os.path.dirname(__file__))).parent.parent / 'terms_and_conditions'
        language = self.config.get('language', 'en_UK')
        path = dir_ / f'{language}.txt'
        if not path.exists():
            path = path.parent / 'en_UK.txt'
            if not path.exists():
                raise FileNotFoundError(f'Cannot open {path}')
        with open(path, 'r') as file:
            return file.read()

    def _render_main_dialog(self, text, run_warning=True):
        vbox = QVBoxLayout()
        text_edit = TermsAndConditionsTextEdit(self.next_button)
        text_edit.setText(text)
        vbox.addWidget(text_edit)
        self.next_button.setText(_('I agree'))
        self.back_button.setText(_('I disagree'))
        try:
            # if user agreed with terms and conditions then result is 2
            # otherwise GoBack exception is raised
            result = self.exec_layout(vbox, title=_('Terms & Conditions'), next_enabled=True)
            if result == 2:
                return True
            return False
        except GoBack:
            if run_warning:
                read_again = self._render_warning_dialog()
                if read_again:
                    return self._render_main_dialog(text, run_warning=False)
            return False

    def _render_warning_dialog(self):
        dialog = WarningDialog(parent=self)
        return dialog.second_chance_for_reading

    def _remove_stretching_from_inner_vbox(self):
        parent_widget = self.main_widget.parentWidget()
        inner_vbox = parent_widget.layout()
        spacer_items = [
            inner_vbox.itemAt(i)
            for i in range(inner_vbox.count()) if inner_vbox.itemAt(i).spacerItem()
        ]
        for item in spacer_items:
            inner_vbox.removeItem(item)

    def accept_terms_and_conditions(self) -> bool:
        self._remove_stretching_from_inner_vbox()
        text = self._read_terms_and_conditions()
        return self._render_main_dialog(text, run_warning=True)
