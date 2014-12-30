from electrum.plugins import BasePlugin, hook
from electrum_gui.qt.util import WaitingDialog
from electrum.util import print_msg

from PyQt4.QtGui import *
from PyQt4.QtCore import *

import traceback
import zlib
import json
from io import BytesIO

try:
    import amodem
    print_msg('Audio MODEM is enabled.')
    amodem_available = True
except ImportError:
    print_msg('Audio MODEM is not found.')
    amodem_available = False


class Plugin(BasePlugin):

    def fullname(self):
        return 'Audio MODEM'

    def description(self):
        return ('Provides support for air-gapped transaction signing.\n\n'
                'Requires http://github.com/romanz/amodem/')

    def is_available(self):
        return amodem_available

    is_enabled = is_available

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

    def _send(self, parent, blob):
        def sender_thread():
            try:
                modem_config = amodem.config.slowest()
                audio_interface = amodem.audio.Interface(modem_config)
                src = BytesIO(blob)
                dst = audio_interface.player()
                amodem.send.main(config=modem_config, src=src, dst=dst)
            except Exception:
                traceback.print_exc()

        print_msg('Sending:', repr(blob))
        blob = zlib.compress(blob)
        return WaitingDialog(
            parent=parent, message='Sending transaction to Audio MODEM...',
            run_task=sender_thread)

    def _recv(self, parent):
        def receiver_thread():
            try:
                modem_config = amodem.config.slowest()
                audio_interface = amodem.audio.Interface(modem_config)
                src = audio_interface.recorder()
                dst = BytesIO()
                amodem.recv.main(config=modem_config, src=src, dst=dst)
                return dst.getvalue()
            except Exception:
                traceback.print_exc()

        def on_success(blob):
            if blob:
                blob = zlib.decompress(blob)
                print_msg('Received:', repr(blob))
                parent.setText(blob)

        return WaitingDialog(
            parent=parent, message='Receiving transaction from Audio MODEM...',
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
