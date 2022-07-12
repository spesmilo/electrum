from functools import partial
from typing import Callable

from electrum.i18n import _
from electrum.plugin import run_hook
from electrum.simple_config import SimpleConfig

from .util import ButtonsTextEdit, MessageBoxMixin, ColorScheme, read_QIcon
from .util import get_iconname_camera, get_iconname_qrcode


class ShowQRTextEdit(ButtonsTextEdit):

    def __init__(self, text=None, *, config: SimpleConfig):
        ButtonsTextEdit.__init__(self, text)
        self.setReadOnly(True)
        self.add_qr_show_button(config=config)
        run_hook('show_text_edit', self)

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(read_QIcon(get_iconname_qrcode()), _("Show as QR code"), self.on_qr_show_btn)
        m.exec_(e.globalPos())


class ScanQRTextEdit(ButtonsTextEdit, MessageBoxMixin):

    def __init__(
            self, text="", allow_multi: bool = False,
            *,
            config: SimpleConfig,
            setText: Callable[[str], None] = None,
    ):
        ButtonsTextEdit.__init__(self, text)
        self.setReadOnly(False)

        input_qr_from_camera = partial(
            self.input_qr_from_camera,
            config=config,
            allow_multi=allow_multi,
            show_error=self.show_error,
            setText=setText,
        )
        self.on_qr_from_camera_input_btn = input_qr_from_camera

        input_qr_from_screenshot = partial(
            self.input_qr_from_screenshot,
            allow_multi=allow_multi,
            show_error=self.show_error,
            setText=setText,
        )
        self.on_qr_from_screenshot_input_btn = input_qr_from_screenshot

        input_file = partial(self.input_file, config=config, show_error=self.show_error, setText=setText)

        self.add_menu_button(
            options=[
                ("picture_in_picture.png", _("Read QR code from screen"), input_qr_from_screenshot),
                ("file.png",               _("Read file"),                input_file),
            ],
        )
        self.add_qr_input_from_camera_button(config=config, show_error=self.show_error, allow_multi=allow_multi, setText=setText)

        run_hook('scan_text_edit', self)

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addSeparator()
        m.addAction(read_QIcon(get_iconname_camera()),    _("Read QR code from camera"), self.on_qr_from_camera_input_btn)
        m.addAction(read_QIcon("picture_in_picture.png"), _("Read QR code from screen"), self.on_qr_from_screenshot_input_btn)
        m.exec_(e.globalPos())


class ScanShowQRTextEdit(ButtonsTextEdit, MessageBoxMixin):

    def __init__(self, text="", allow_multi: bool = False, *, config: SimpleConfig):
        ButtonsTextEdit.__init__(self, text)
        self.setReadOnly(False)
        self.add_qr_input_combined_button(config=config, show_error=self.show_error, allow_multi=allow_multi)
        self.add_qr_show_button(config=config)
        run_hook('scan_text_edit', self)
        run_hook('show_text_edit', self)

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addSeparator()
        m.addAction(read_QIcon(get_iconname_camera()),    _("Read QR code from camera"), self.on_qr_from_camera_input_btn)
        m.addAction(read_QIcon("picture_in_picture.png"), _("Read QR code from screen"), self.on_qr_from_screenshot_input_btn)
        m.addAction(read_QIcon(get_iconname_qrcode()),    _("Show as QR code"),          self.on_qr_show_btn)
        m.exec_(e.globalPos())
