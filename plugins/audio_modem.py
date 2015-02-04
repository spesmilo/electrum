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

    def fullname(self):
        return 'Audio MODEM'

    def description(self):
        return ('Provides support for air-gapped transaction signing.\n\n'
                'Requires http://github.com/romanz/amodem/')

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
        dialog.buttons.insertWidget(1, b)

    @hook
    def scan_text_edit(self, parent):
        def handler():
            self.receiver = self._recv(parent=parent)
            self.receiver.start()
        button = add_button(parent=parent, icon_name=':icons/microphone.png')
        button.clicked.connect(handler)

    @hook
    def show_text_edit(self, parent):
        def handler():
            blob = str(parent.toPlainText())
            self.sender = self._send(parent=parent, blob=blob)
            self.sender.start()
        button = add_button(parent=parent, icon_name=':icons/speaker.png')
        button.clicked.connect(handler)

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


def add_button(parent, icon_name):
    audio_button = QToolButton(parent)
    audio_button.setIcon(QIcon(icon_name))
    audio_button.setStyleSheet("QToolButton { border: none; padding: 0px; }")
    audio_button.setVisible(True)

    parent_resizeEvent = parent.resizeEvent

    def resizeEvent(e):
        result = parent_resizeEvent(e)
        qr_button = parent.button
        left = qr_button.geometry().left() - audio_button.sizeHint().width()
        top = qr_button.geometry().top()
        audio_button.move(left, top)
        return result

    parent.resizeEvent = resizeEvent
    return audio_button
