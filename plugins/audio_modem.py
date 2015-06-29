from electrum.plugins import BasePlugin, hook
from electrum_gui.qt.util import WaitingDialog, EnterButton
from electrum.util import print_msg, print_error
from electrum.i18n import _

from PyQt4.QtGui import *
from PyQt4.QtCore import *

import traceback
import zlib
import json
from io import BytesIO
import sys
import platform

try:
    import amodem.audio
    import amodem.main
    import amodem.config
    print_error('Audio MODEM is available.')
    amodem.log.addHandler(amodem.logging.StreamHandler(sys.stderr))
    amodem.log.setLevel(amodem.logging.INFO)
except ImportError:
    amodem = None
    print_error('Audio MODEM is not found.')


class Plugin(BasePlugin):

    def __init__(self, config, name):
        BasePlugin.__init__(self, config, name)
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
        return EnterButton(_('Settings'), self.settings_dialog)

    def settings_dialog(self):
        d = QDialog()
        d.setWindowTitle("Settings")

        layout = QGridLayout(d)
        layout.addWidget(QLabel(_('Bit rate [kbps]: ')), 0, 0)

        bitrates = list(sorted(amodem.config.bitrates.keys()))

        def _index_changed(index):
            bitrate = bitrates[index]
            self.modem_config = amodem.config.bitrates[bitrate]

        combo = QComboBox()
        combo.addItems(map(str, bitrates))
        combo.currentIndexChanged.connect(_index_changed)
        layout.addWidget(combo, 0, 1)

        ok_button = QPushButton(_("OK"))
        ok_button.clicked.connect(d.accept)
        layout.addWidget(ok_button, 1, 1)

        return bool(d.exec_())

    @hook
    def transaction_dialog(self, dialog):
        b = QPushButton()
        b.setIcon(QIcon(":icons/speaker.png"))

        def handler():
            blob = json.dumps(dialog.tx.as_dict())
            self.sender = self._send(parent=dialog, blob=blob)
            self.sender.start()
        b.clicked.connect(handler)
        dialog.sharing_buttons.insert(-1, b)

    @hook
    def scan_text_edit(self, parent):
        def handler():
            self.receiver = self._recv(parent=parent)
            self.receiver.start()
        parent.addButton(':icons/microphone.png', handler, _("Read from microphone"))

    @hook
    def show_text_edit(self, parent):
        def handler():
            blob = str(parent.toPlainText())
            self.sender = self._send(parent=parent, blob=blob)
            self.sender.start()
        parent.addButton(':icons/speaker.png', handler, _("Send to speaker"))

    def _audio_interface(self):
        interface = amodem.audio.Interface(config=self.modem_config)
        return interface.load(self.library_name)

    def _send(self, parent, blob):
        def sender_thread():
            try:
                with self._audio_interface() as interface:
                    src = BytesIO(blob)
                    dst = interface.player()
                    amodem.main.send(config=self.modem_config, src=src, dst=dst)
            except Exception:
                traceback.print_exc()

        print_msg('Sending:', repr(blob))
        blob = zlib.compress(blob)

        kbps = self.modem_config.modem_bps / 1e3
        msg = 'Sending to Audio MODEM ({0:.1f} kbps)...'.format(kbps)
        return WaitingDialog(parent=parent, message=msg, run_task=sender_thread)

    def _recv(self, parent):
        def receiver_thread():
            try:
                with self._audio_interface() as interface:
                    src = interface.recorder()
                    dst = BytesIO()
                    amodem.main.recv(config=self.modem_config, src=src, dst=dst)
                    return dst.getvalue()
            except Exception:
                traceback.print_exc()

        def on_success(blob):
            if blob:
                blob = zlib.decompress(blob)
                print_msg('Received:', repr(blob))
                parent.setText(blob)

        kbps = self.modem_config.modem_bps / 1e3
        msg = 'Receiving from Audio MODEM ({0:.1f} kbps)...'.format(kbps)
        return WaitingDialog(parent=parent, message=msg,
                             run_task=receiver_thread, on_success=on_success)


