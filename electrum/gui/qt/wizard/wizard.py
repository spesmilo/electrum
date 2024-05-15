import copy
import threading
from abc import abstractmethod
from typing import TYPE_CHECKING

from PyQt5.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot, QSize, QMetaObject
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (QDialog, QPushButton, QWidget, QLabel, QVBoxLayout, QScrollArea,
                             QHBoxLayout, QLayout)

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.gui.qt.util import Buttons, icon_path, MessageBoxMixin, WWLabel, ResizableStackedWidget, AbstractQWidget

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.gui.qt import QElectrumApplication
    from electrum.wizard import WizardViewState


class QEAbstractWizard(QDialog, MessageBoxMixin):
    """ Concrete subclasses of QEAbstractWizard must also inherit from a concrete AbstractWizard subclass.
        QEAbstractWizard forms the base for all QtWidgets GUI based wizards, while AbstractWizard defines
        the base for non-gui wizard flow navigation functionality.
    """
    _logger = get_logger(__name__)

    requestNext = pyqtSignal()
    requestPrev = pyqtSignal()

    def __init__(self, config: 'SimpleConfig', app: 'QElectrumApplication', *, start_viewstate: 'WizardViewState' = None):
        QDialog.__init__(self, None)
        self.app = app
        self.config = config

        # compat
        self.gui_thread = threading.current_thread()

        self.setMinimumSize(600, 400)

        self.title = QLabel()
        self.window_title = ''
        self.finish_label = _('Finish')

        self.main_widget = ResizableStackedWidget(self)

        self.back_button = QPushButton(_("Back"), self)
        self.back_button.clicked.connect(self.on_back_button_clicked)
        self.back_button.setEnabled(False)
        self.next_button = QPushButton(_("Next"), self)
        self.next_button.clicked.connect(self.on_next_button_clicked)
        self.next_button.setEnabled(False)
        self.next_button.setDefault(True)
        self.requestPrev.connect(self.on_back_button_clicked)
        self.requestNext.connect(self.on_next_button_clicked)
        self.logo = QLabel()

        please_wait_layout = QVBoxLayout()
        please_wait_layout.addStretch(1)
        self.please_wait_l = QLabel(_("Please wait..."))
        self.please_wait_l.setAlignment(Qt.AlignCenter)
        please_wait_layout.addWidget(self.please_wait_l)
        please_wait_layout.addStretch(1)
        self.please_wait = QWidget()
        self.please_wait.setVisible(False)
        self.please_wait.setLayout(please_wait_layout)

        error_layout = QVBoxLayout()
        error_layout.addStretch(1)
        error_icon = QLabel()
        error_icon.setPixmap(QPixmap(icon_path('warning.png')).scaledToWidth(48, mode=Qt.SmoothTransformation))
        error_icon.setAlignment(Qt.AlignCenter)
        error_layout.addWidget(error_icon)
        self.error_msg = WWLabel()
        self.error_msg.setAlignment(Qt.AlignCenter)
        error_layout.addWidget(self.error_msg)
        error_layout.addStretch(1)
        self.error = QWidget()
        self.error.setVisible(False)
        self.error.setLayout(error_layout)

        outer_vbox = QVBoxLayout(self)
        inner_vbox = QVBoxLayout()
        inner_vbox.addWidget(self.title)
        inner_vbox.addWidget(self.main_widget)
        inner_vbox.addWidget(self.please_wait)
        inner_vbox.addWidget(self.error)

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

        self.start_viewstate = start_viewstate

        self.show()
        self.raise_()

        QMetaObject.invokeMethod(self, 'strt', Qt.QueuedConnection)  # call strt after subclass constructor(s)

    def sizeHint(self) -> QSize:
        return QSize(600, 400)

    @pyqtSlot()
    def strt(self):
        if self.start_viewstate is not None:
            viewstate = self._current = self.start_viewstate
        else:
            viewstate = self.start_wizard()
        self.load_next_component(viewstate.view, viewstate.wizard_data, viewstate.params)
        # TODO: re-test if needed on macOS
        self.refresh_gui()  # Need for QT on MacOSX.  Lame.
        self.next_button.setFocus() # setDefault() is not enough

    def refresh_gui(self):
        # For some reason, to refresh the GUI this needs to be called twice
        self.app.processEvents()
        self.app.processEvents()

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
        page.wizard_data = copy.deepcopy(wdata)
        page.params = params
        page.on_ready()  # call before component emits any signals

        self._logger.debug(f'load_next_component: {page=!r}')

        page.updated.connect(self.on_page_updated)

        # add to stack and update wizard
        self.main_widget.setCurrentIndex(self.main_widget.addWidget(page))
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
        self.setWindowTitle(page.wizard_title if page.wizard_title else self.window_title)
        self.title.setText(f'<b>{page.title}</b>' if page.title else '')
        self.back_button.setText(_('Back') if self.can_go_back() else _('Cancel'))
        self.back_button.setEnabled(not page.busy)
        self.next_button.setText(_('Next') if not self.is_last(page.wizard_data) else self.finish_label)
        self.next_button.setEnabled(not page.busy and page.valid)
        self.main_widget.setVisible(not page.busy and not bool(page.error))
        self.please_wait.setVisible(page.busy)
        self.please_wait_l.setText(page.busy_msg if page.busy_msg else _("Please wait..."))
        self.error_msg.setText(str(page.error))
        self.error.setVisible(not page.busy and bool(page.error))
        icon = page.params.get('icon', icon_path('electrum.png'))
        if icon:
            if icon != self.icon_filename:
                self.set_icon(icon)
            self.logo.setVisible(True)
        else:
            self.logo.setVisible(False)

    def on_back_button_clicked(self):
        if self.can_go_back():
            self.prev()
            widget = self.main_widget.currentWidget()
            self.main_widget.removeWidget(widget)
            widget.deleteLater()
            self.update()
        else:
            self.close()

    def on_next_button_clicked(self):
        page = self.main_widget.currentWidget()
        page.apply()
        wd = page.wizard_data.copy()
        if self.is_last(wd):
            self.submit(wd)
            if self.is_finalized(wd):
                self.accept()
            else:
                self.prev()  # rollback the submit above
        else:
            next = self.submit(wd)
            self.load_next_component(next.view, next.wizard_data, next.params)

    def start_wizard(self) -> 'WizardViewState':
        self.start()
        return self._current

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

    def is_finalized(self, wizard_data: dict) -> bool:
        ''' Final check before closing the wizard. '''
        return True


class WizardComponent(AbstractQWidget):
    updated = pyqtSignal(object)

    def __init__(self, parent: QWidget, wizard: QEAbstractWizard, *, title: str = None, layout: QLayout = None):
        super().__init__(parent)
        self.setLayout(layout if layout else QVBoxLayout(self))
        self.wizard_data = {}
        self.title = title if title is not None else 'No title'
        self.wizard_title = None
        self.busy_msg = ''
        self.wizard = wizard
        self._error = ''
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

    @property
    def error(self):
        return self._error

    @error.setter
    def error(self, error):
        if self._error != error:
            self._error = error
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
        try:
            self.updated.emit(self)
        except RuntimeError:
            pass
