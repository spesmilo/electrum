from functools import partial
import zlib
import json
from io import BytesIO
import sys
import platform

from PyQt5.QtWidgets import (QComboBox, QGridLayout, QLabel, QPushButton)

from electrum.plugin import BasePlugin, hook
from electrum.gui.qt.util import WaitingDialog, EnterButton, WindowModalDialog, read_QIcon
from electrum.i18n import _
from electrum.logging import get_logger


_logger = get_logger(__name__)


try:
    import amodem.audio
    import amodem.main
    import amodem.config
    _logger.info('Audio MODEM is available.')
    amodem.log.addHandler(amodem.logging.StreamHandler(sys.stderr))
    amodem.log.setLevel(amodem.logging.INFO)
except ImportError:
    amodem = None
    _logger.info('Audio MODEM is not found.')


class Plugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        if self.is_available():
            self.modem_config = amodem.config.slowest()
            self.library_name = {
                'Linux': 'libportaudio.so'
            }[platform.system()]

    def is_available(self):
        return amodem is not None

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'), partial(self.settings_dialog, window))

    def settings_dialog(self, window):
        d = WindowModalDialog(window, _("Audio Modem Settings"))

        layout = QGridLayout(d)
        layout.addWidget(QLabel(_('Bit rate [kbps]: ')), 0, 0)

        bitrates = list(sorted(amodem.config.bitrates.keys()))

        def _index_changed(index):
            bitrate = bitrates[index]
            self.modem_config = amodem.config.bitrates[bitrate]

        combo = QComboBox()
        combo.addItems([str(x) for x in bitrates])
        combo.currentIndexChanged.connect(_index_changed)
        layout.addWidget(combo, 0, 1)

        ok_button = QPushButton(_("OK"))
        ok_button.clicked.connect(d.accept)
        layout.addWidget(ok_button, 1, 1)

        return bool(d.exec_())

    @hook
    def transaction_dialog(self, dialog):
        b = QPushButton()
        b.setIcon(read_QIcon("speaker.png"))

        def handler():
            blob = json.dumps(dialog.tx.as_dict())
            self._send(parent=dialog, blob=blob)
        b.clicked.connect(handler)
        dialog.sharing_buttons.insert(-1, b)

    @hook
    def scan_text_edit(self, parent):
        parent.addButton('microphone.png', partial(self._recv, parent),
                         _("Read from microphone"))

    @hook
    def show_text_edit(self, parent):
        def handler():
            blob = str(parent.toPlainText())
            self._send(parent=parent, blob=blob)
        parent.addButton('speaker.png', handler, _("Send to speaker"))

    def _audio_interface(self):
        interface = amodem.audio.Interface(config=self.modem_config)
        return interface.load(self.library_name)

    def _send(self, parent, blob):
        def sender_thread():
            with self._audio_interface() as interface:
                src = BytesIO(blob)
                dst = interface.player()
                amodem.main.send(config=self.modem_config, src=src, dst=dst)

        _logger.info(f'Sending: {repr(blob)}')
        blob = zlib.compress(blob.encode('ascii'))

        kbps = self.modem_config.modem_bps / 1e3
        msg = 'Sending to Audio MODEM ({0:.1f} kbps)...'.format(kbps)
        WaitingDialog(parent, msg, sender_thread)

    def _recv(self, parent):
        def receiver_thread():
            with self._audio_interface() as interface:
                src = interface.recorder()
                dst = BytesIO()
                amodem.main.recv(config=self.modem_config, src=src, dst=dst)
                return dst.getvalue()

        def on_finished(blob):
            if blob:
                blob = zlib.decompress(blob).decode('ascii')
                _logger.info(f'Received: {repr(blob)}')
                parent.setText(blob)

        kbps = self.modem_config.modem_bps / 1e3
        msg = 'Receiving from Audio MODEM ({0:.1f} kbps)...'.format(kbps)
        WaitingDialog(parent, msg, receiver_thread, on_finished)
