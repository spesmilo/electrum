from functools import partial
from typing import Callable

from electrum.i18n import _
from electrum.plugin import run_hook
from electrum.simple_config import SimpleConfig

from .util import ButtonsTextEdit, MessageBoxMixin, ColorScheme, read_QIcon
from .util import get_icon_camera, get_icon_qrcode, add_input_actions_to_context_menu


class ShowQRTextEdit(ButtonsTextEdit):

    def __init__(self, text=None, *, config: SimpleConfig):
        ButtonsTextEdit.__init__(self, text)
        self.setReadOnly(True)
        self.add_qr_show_button(config=config)
        run_hook('show_text_edit', self)

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(get_icon_qrcode(), _("Show as QR code"), self.on_qr_show_btn)
        m.exec(e.globalPos())


class ScanQRTextEdit(ButtonsTextEdit, MessageBoxMixin):

    def __init__(
            self, text="", allow_multi: bool = False,
            *,
            config: SimpleConfig,
            setText: Callable[[str], None] = None,
            is_payto = False,
    ):
        ButtonsTextEdit.__init__(self, text)
        self.setReadOnly(False)
        self.on_qr_from_camera_input_btn = partial(
            self.input_qr_from_camera,
            config=config,
            allow_multi=allow_multi,
            show_error=self.show_error,
            setText=setText,
        )
        self.on_qr_from_screenshot_input_btn = partial(
            self.input_qr_from_screenshot,
            allow_multi=allow_multi,
            show_error=self.show_error,
            setText=setText,
        )
        self.on_qr_from_file_input_btn = partial(
            self.input_qr_from_file,
            allow_multi=allow_multi,
            config=config,
            show_error=self.show_error,
            setText=setText,
        )
        self.on_input_file = partial(
            self.input_file,
            config=config,
            show_error=self.show_error,
            setText=setText,
        )
        # for send tab, buttons are available in the toolbar
        if not is_payto:
            self.add_input_buttons(config, allow_multi, setText)
        run_hook('scan_text_edit', self)

    def add_input_buttons(self, config, allow_multi, setText):
        self.add_menu_button(
            options=[
                ("picture_in_picture.png", _("Read QR code from screen"), self.on_qr_from_screenshot_input_btn),
                ("qr_file.png",            _("Read QR code from file"),   self.on_qr_from_file_input_btn),
                ("file.png",               _("Read text from file"),      self.on_input_file),
            ],
        )
        self.add_qr_input_from_camera_button(config=config, show_error=self.show_error, allow_multi=allow_multi, setText=setText)

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addSeparator()
        add_input_actions_to_context_menu(self, m)
        m.exec(e.globalPos())


class ScanShowQRTextEdit(ScanQRTextEdit):

    def __init__(self, *args, config: SimpleConfig, **kwargs):
        ScanQRTextEdit.__init__(self, *args, **kwargs, config=config)
        self.add_qr_show_button(config=config)
        run_hook('show_text_edit', self)

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addSeparator()
        add_input_actions_to_context_menu(self, m)
        m.addAction(get_icon_qrcode(), _("Show as QR code"), self.on_qr_show_btn)
        m.exec(e.globalPos())
