from functools import partial
from typing import Callable

from electrum.i18n import _
from electrum.plugin import run_hook
from electrum.simple_config import SimpleConfig

from .util import ButtonsTextEdit, MessageBoxMixin, ColorScheme, getOpenFileName
from .qrreader import scan_qrcode


def qr_show(text_edit, *, config: SimpleConfig) -> None:
    from .qrcodewidget import QRDialog
    try:
        s = str(text_edit.text())
    except:
        s = text_edit.text()
    if not s:
        return
    QRDialog(
        data=s,
        parent=text_edit,
        config=config,
    ).exec_()


def qr_input(
        text_edit,
        *,
        config: SimpleConfig,
        allow_multi: bool = False,
        show_error: Callable[[str], None],
) -> None:
    def cb(success: bool, error: str, data):
        if not success:
            if error:
                show_error(error)
            return
        if not data:
            data = ''
        if allow_multi:
            new_text = text_edit.text() + data + '\n'
        else:
            new_text = data
        text_edit.setText(new_text)

    scan_qrcode(parent=text_edit, config=config, callback=cb)


def file_input(
        text_edit,
        *,
        config: SimpleConfig,
        show_error: Callable[[str], None],
) -> None:
    fileName = getOpenFileName(
        parent=text_edit,
        title='select file',
        config=config,
    )
    if not fileName:
        return
    try:
        try:
            with open(fileName, "r") as f:
                data = f.read()
        except UnicodeError as e:
            with open(fileName, "rb") as f:
                data = f.read()
            data = data.hex()
    except BaseException as e:
        show_error(_('Error opening file') + ':\n' + repr(e))
    else:
        text_edit.setText(data)


class ShowQRTextEdit(ButtonsTextEdit):

    def __init__(self, text=None, *, config: SimpleConfig):
        ButtonsTextEdit.__init__(self, text)
        self.config = config
        self.setReadOnly(True)
        # qr_show
        self.qr_show = partial(qr_show, self, config=config)
        icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self.addButton(icon, self.qr_show, _("Show as QR code"))

        run_hook('show_text_edit', self)

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(_("Show as QR code"), self.qr_show)
        m.exec_(e.globalPos())


class ScanQRTextEdit(ButtonsTextEdit, MessageBoxMixin):

    def __init__(self, text="", allow_multi: bool = False, *, config: SimpleConfig):
        ButtonsTextEdit.__init__(self, text)
        self.config = config
        self.setReadOnly(False)
        # file_input
        self.file_input = partial(file_input, self, config=config, show_error=self.show_error)
        self.addButton("file.png", self.file_input, _("Read file"))
        # qr_input
        self.qr_input = partial(qr_input, self, config=config, show_error=self.show_error, allow_multi=allow_multi)
        icon = "camera_white.png" if ColorScheme.dark_scheme else "camera_dark.png"
        self.addButton(icon, self.qr_input, _("Read QR code"))

        run_hook('scan_text_edit', self)

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(_("Read QR code"), self.qr_input)
        m.exec_(e.globalPos())


class ScanShowQRTextEdit(ButtonsTextEdit, MessageBoxMixin):

    def __init__(self, text="", allow_multi: bool = False, *, config: SimpleConfig):
        ButtonsTextEdit.__init__(self, text)
        self.config = config
        self.setReadOnly(False)
        # qr_input
        self.qr_input = partial(qr_input, self, config=config, show_error=self.show_error, allow_multi=allow_multi)
        icon = "camera_white.png" if ColorScheme.dark_scheme else "camera_dark.png"
        self.addButton(icon, self.qr_input, _("Read QR code"))
        # qr_show
        self.qr_show = partial(qr_show, self, config=config)
        icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self.addButton(icon, self.qr_show, _("Show as QR code"))

        run_hook('scan_text_edit', self)
        run_hook('show_text_edit', self)

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(_("Read QR code"), self.qr_input)
        m.addAction(_("Show as QR code"), self.qr_show)
        m.exec_(e.globalPos())
