from abc import abstractmethod
from typing import TYPE_CHECKING

from PyQt5.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot, QSize
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (QDialog, QApplication, QPushButton, QWidget, QLabel, QVBoxLayout, QScrollArea,
                             QHBoxLayout, QLayout, QStackedWidget)

from electrum.i18n import _
from ..util import Buttons, icon_path
from electrum.logging import get_logger

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.plugin import Plugins
    from electrum.daemon import Daemon
    from electrum.gui.qt import QElectrumApplication


class QEAbstractWizard(QDialog):
    _logger = get_logger(__name__)

    # def __init__(self, config: 'SimpleConfig', app: QApplication, plugins: 'Plugins', *, gui_object: 'ElectrumGui'):
    def __init__(self, config: 'SimpleConfig', app: 'QElectrumApplication', plugins: 'Plugins', daemon: 'Daemon'):
        QDialog.__init__(self, None)
        self.app = app
        self.config = config
        self.plugins = plugins
        # self.gui_thread = gui_object.gui_thread
        self.setMinimumSize(600, 400)

        self.title = QLabel()

        self.main_widget = QStackedWidget(self)

        self.back_button = QPushButton(_("Back"), self)
        self.back_button.clicked.connect(self.on_back_button_clicked)
        self.next_button = QPushButton(_("Next"), self)
        self.next_button.clicked.connect(self.on_next_button_clicked)
        self.next_button.setDefault(True)

        self.logo = QLabel()

        self.please_wait_layout = QVBoxLayout()
        self.please_wait_layout.addStretch(1)
        self.please_wait = QLabel(_("Please wait..."))
        self.please_wait.setAlignment(Qt.AlignCenter)
        self.please_wait.setVisible(False)
        self.please_wait_layout.addWidget(self.please_wait)
        self.please_wait_layout.addStretch(1)

        outer_vbox = QVBoxLayout(self)
        inner_vbox = QVBoxLayout()
        inner_vbox.addWidget(self.title)
        inner_vbox.addWidget(self.main_widget)
        inner_vbox.addLayout(self.please_wait_layout)
        scroll_widget = QWidget()
        scroll_widget.setLayout(inner_vbox)
        scroll = QScrollArea()
        scroll.setFocusPolicy(Qt.NoFocus)
        scroll.setWidget(scroll_widget)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidgetResizable(True)
        icon_vbox = QVBoxLayout()
        icon_vbox.addWidget(self.logo)
        icon_vbox.addStretch(1)
        hbox = QHBoxLayout()
        hbox.addLayout(icon_vbox)
        hbox.addSpacing(5)
        hbox.addWidget(scroll)
        hbox.setStretchFactor(scroll, 1)
        outer_vbox.addLayout(hbox)
        outer_vbox.addLayout(Buttons(self.back_button, self.next_button))

        self.icon_filename = None
        self.set_icon('electrum.png')

        self.show()
        self.raise_()

        QTimer.singleShot(40, self.strt)

        # TODO: re-test if needed on macOS
        # self.refresh_gui()  # Need for QT on MacOSX.  Lame.

    # def refresh_gui(self):
    #     # For some reason, to refresh the GUI this needs to be called twice
    #     self.app.processEvents()
    #     self.app.processEvents()

    def sizeHint(self) -> QSize:
        return QSize(800, 600)

    def strt(self):
        view = self.start_wizard()
        self.load_next_component(view)

    def load_next_component(self, view, wdata=None, params=None):
        if wdata is None:
            wdata = {}
        if params is None:
            params = {}

        comp = self.view_to_component(view)
        try:
            page = comp(self.main_widget, self)
        except Exception as e:
            self._logger.error(f'not a class: {comp!r}')
            raise e
        page.wizard_data = wdata
        page.params = params
        page.updated.connect(self.on_page_updated)
        self._logger.debug(f'{page!r}')

        # add to stack and update wizard
        self.main_widget.setCurrentIndex(self.main_widget.addWidget(page))
        page.on_ready()
        page.apply()
        self.update()

    @pyqtSlot(object)
    def on_page_updated(self, page):
        page.apply()
        if page == self.main_widget.currentWidget():
            self.update()

    def set_icon(self, filename):
        prior_filename, self.icon_filename = self.icon_filename, filename
        self.logo.setPixmap(QPixmap(icon_path(filename))
                            .scaledToWidth(60, mode=Qt.SmoothTransformation))
        return prior_filename

    def can_go_back(self) -> bool:
        return len(self._stack) > 0

    def update(self):
        page = self.main_widget.currentWidget()
        self.title.setText(f'<b>{page.title}</b>' if page.title else '')
        self.back_button.setText(_('Back') if self.can_go_back() else _('Cancel'))
        self.next_button.setText(_('Next') if not self.is_last(page.wizard_data) else _('Finish'))
        self.next_button.setEnabled(page.valid)
        self.main_widget.setVisible(not page.busy)
        self.please_wait.setVisible(page.busy)
        icon = page.params.get('icon', icon_path('electrum.png'))
        if icon != self.icon_filename:
            self.set_icon(icon)

    def on_back_button_clicked(self):
        if self.can_go_back():
            self.prev()
            self.main_widget.removeWidget(self.main_widget.currentWidget())
            self.update()
        else:
            self.close()

    def on_next_button_clicked(self):
        page = self.main_widget.currentWidget()
        page.apply()
        wd = page.wizard_data.copy()
        if self.is_last(wd):
            self.submit(wd)
            self.finished(wd)
            self.accept()
        else:
            next = self.submit(wd)
            self.load_next_component(next.view, next.wizard_data, next.params)

    def start_wizard(self) -> str:
        self.start()
        return self._current.view

    def view_to_component(self, view) -> QWidget:
        return self.navmap[view]['gui']

    def submit(self, wizard_data) -> dict:
        wdata = wizard_data.copy()
        view = self.resolve_next(self._current.view, wdata)
        return view

    def prev(self) -> dict:
        viewstate = self.resolve_prev()
        return viewstate.wizard_data

    def is_last(self, wizard_data: dict) -> bool:
        wdata = wizard_data.copy()
        return self.is_last_view(self._current.view, wdata)


class WizardComponent(QWidget):
    updated = pyqtSignal(object)

    def __init__(self, parent: QWidget, wizard: QEAbstractWizard, *, title: str = None, layout: QLayout = None):
        super().__init__(parent)
        self.setLayout(layout if layout else QVBoxLayout(self))
        self.wizard_data = {}
        self.title = title if title is not None else 'No title'
        self.wizard = wizard
        self._valid = False
        self._busy = False

    @property
    def valid(self):
        return self._valid

    @valid.setter
    def valid(self, is_valid):
        if self._valid != is_valid:
            self._valid = is_valid
            self.on_updated()

    @property
    def busy(self):
        return self._busy

    @busy.setter
    def busy(self, is_busy):
        if self._busy != is_busy:
            self._busy = is_busy
            self.on_updated()

    @abstractmethod
    def apply(self):
        # called to apply UI component values to wizard_data
        pass

    def on_ready(self):
        # called when wizard_data is available
        pass

    @pyqtSlot()
    def on_updated(self, *args):
        self.updated.emit(self)

    # returns (sub)dict of current cosigner (or root if first)
    def _current_cosigner(self, wizard_data):
        wdata = wizard_data
        if wizard_data['wallet_type'] == 'multisig' and 'multisig_current_cosigner' in wizard_data:
            cosigner = wizard_data['multisig_current_cosigner']
            wdata = wizard_data['multisig_cosigner_data'][str(cosigner)]
        return wdata
