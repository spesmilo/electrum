import threading

from PyQt6.QtCore import pyqtProperty, pyqtSignal, QObject

from electrum.util import get_version_info

from electrum.gui.common_qt.util import ignore_if_destroyed


class QEVersionInfo(QObject):
    """Output of the version_info command, collected in a thread as that imports modules
    and loads shared libraries."""
    textChanged = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._text = ''
        threading.Thread(target=self._load, daemon=True).start()

    @pyqtProperty(str, notify=textChanged)
    def text(self):
        return self._text

    def _load(self):
        text = '\n'.join(f'{k}: {v}' for k, v in get_version_info().items())
        with ignore_if_destroyed(self):
            self._text = text
            self.textChanged.emit()
