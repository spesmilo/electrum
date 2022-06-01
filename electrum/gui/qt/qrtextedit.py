from electrum.i18n import _
from electrum.plugin import run_hook
from electrum.simple_config import SimpleConfig

from .util import ButtonsTextEdit, MessageBoxMixin


class ShowQRTextEdit(ButtonsTextEdit):

    def __init__(self, text=None, *, config: SimpleConfig):
        ButtonsTextEdit.__init__(self, text)
        self.setReadOnly(True)
        self.add_qr_show_button(config=config)
        run_hook('show_text_edit', self)

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(_("Show as QR code"), self.on_qr_show_btn)
        m.exec_(e.globalPos())


class ScanQRTextEdit(ButtonsTextEdit, MessageBoxMixin):

    def __init__(self, text="", allow_multi: bool = False, *, config: SimpleConfig):
        ButtonsTextEdit.__init__(self, text)
        self.setReadOnly(False)
        self.add_file_input_button(config=config, show_error=self.show_error)
        self.add_qr_input_button(config=config, show_error=self.show_error, allow_multi=allow_multi)
        run_hook('scan_text_edit', self)

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addSeparator()
        m.addAction(_("Read QR code from camera"), self.on_qr_from_camera_input_btn)
        m.addAction(_("Read QR code from screen"), self.on_qr_from_screenshot_input_btn)
        m.exec_(e.globalPos())


class ScanShowQRTextEdit(ButtonsTextEdit, MessageBoxMixin):

    def __init__(self, text="", allow_multi: bool = False, *, config: SimpleConfig):
        ButtonsTextEdit.__init__(self, text)
        self.setReadOnly(False)
        self.add_qr_input_button(config=config, show_error=self.show_error, allow_multi=allow_multi)
        self.add_qr_show_button(config=config)
        run_hook('scan_text_edit', self)
        run_hook('show_text_edit', self)

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addSeparator()
        m.addAction(_("Read QR code from camera"), self.on_qr_from_camera_input_btn)
        m.addAction(_("Read QR code from screen"), self.on_qr_from_screenshot_input_btn)
        m.addAction(_("Show as QR code"), self.on_qr_show_btn)
        m.exec_(e.globalPos())
