from abc import abstractmethod

from PyQt5.QtCore import Qt, QVariant, QTimer, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (QDialog, QApplication, QPushButton, QWidget, QLabel, QVBoxLayout, QScrollArea,
                             QHBoxLayout, QLayout, QStackedWidget)

from electrum.i18n import _
from ..util import Buttons, icon_path
from electrum.logging import get_logger


class QEAbstractWizard(QDialog):
    _logger = get_logger(__name__)

    # def __init__(self, config: 'SimpleConfig', app: QApplication, plugins: 'Plugins', *, gui_object: 'ElectrumGui'):
    def __init__(self, config: 'SimpleConfig', app: QApplication, daemon):
        QDialog.__init__(self, None)
        self.app = app
        self.config = config
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
        self.please_wait = QLabel(_("Please wait..."))
        self.please_wait.setAlignment(Qt.AlignCenter)
        self.please_wait.setVisible(False)
        self.icon_filename = None

        outer_vbox = QVBoxLayout(self)
        inner_vbox = QVBoxLayout()
        inner_vbox.addWidget(self.title)
        inner_vbox.addWidget(self.main_widget)
        inner_vbox.addStretch(1)
        inner_vbox.addWidget(self.please_wait)
        inner_vbox.addStretch(1)
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

    def strt(self):
        view = self.start_wizard()
        self.load_next_component(view)

    def load_next_component(self, view, wdata={}):
        comp = self.view_to_component(view)
        page = comp(self.main_widget)
        page.wizard_data = wdata
        page.updated.connect(self.on_page_updated)
        self._logger.debug(f'{page!r}')
        self.main_widget.setCurrentIndex(self.main_widget.addWidget(page))
        page.apply()
        self.update(page.wizard_data)

    @pyqtSlot(object)
    def on_page_updated(self, page):
        page.apply()
        self.update(page.wizard_data)

    def set_icon(self, filename):
        prior_filename, self.icon_filename = self.icon_filename, filename
        self.logo.setPixmap(QPixmap(icon_path(filename))
                            .scaledToWidth(60, mode=Qt.SmoothTransformation))
        return prior_filename

    def can_go_back(self):
        return len(self._stack) > 0

    def update(self, wdata: dict):
        self.back_button.setText(_('Back') if self.can_go_back() else _('Cancel'))
        self.next_button.setText(_('Next') if not self.is_last(wdata) else _('Finish'))

    def on_back_button_clicked(self):
        if self.can_go_back():
            wdata = self.prev()
            self.main_widget.removeWidget(self.main_widget.currentWidget())
            self.update(wdata)
        else:
            self.close()

    def on_next_button_clicked(self):
        wc = self.main_widget.currentWidget()
        wc.apply()
        wd = wc.wizard_data.copy()
        if self.is_last(wd):
            self.finished(wd)
            self.close()
        else:
            next = self.submit(wd)
            self.load_next_component(next['view'], wd)

    def start_wizard(self) -> str:
        self.start()
        return self._current.view

    def view_to_component(self, view) -> QWidget:
        return self.navmap[view]['gui']

    def submit(self, wizard_data) -> dict:
        wdata = wizard_data.copy()
        self.log_state(wdata)
        view = self.resolve_next(self._current.view, wdata)
        return {
            'view': view.view,
            'wizard_data': view.wizard_data
        }

    def prev(self) -> dict:
        viewstate = self.resolve_prev()
        return viewstate.wizard_data

    def is_last(self, wizard_data: dict) -> bool:
        wdata = wizard_data.copy()
        return self.is_last_view(self._current.view, wdata)


### support classes


class WizardComponent(QWidget):
    updated = pyqtSignal(object)

    def __init__(self, parent: QWidget = None, *, title: str = None, layout: QLayout = None):
        super().__init__(parent)
        self.setLayout(layout if layout else QVBoxLayout(self))
        self.wizard_data = {}
        self.title = title if title is not None else 'No title'
        self._valid = False

    @property
    def valid(self):
        return self._valid

    @abstractmethod
    def apply(self):
        pass

    @pyqtSlot()
    def on_updated(self, *args):
        self.updated.emit(self)

