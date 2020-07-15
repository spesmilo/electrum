import copy
from enum import IntEnum
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QVBoxLayout, QTextEdit, QLineEdit, QLabel
from .qrcodewidget import QRCodeWidget
from electrum.ecc import ECPubkey, ECPrivkey
from electrum.i18n import _
from ...three_keys import short_mnemonic


class ValidationState(IntEnum):
    INVALID = 0
    VALID = 1
    INTERMEDIATE = 2
    CROPPED = 3


class PubKeyValidator:
    COMPRESSED_PREFIXES = ('02', '03')
    UNCOMPRESSED_PREFIXES = '04'
    COMPRESSED_PUBKEY_LENGTH = 66
    UNCOMPRESSED_PUBKEY_LENGTH = 130

    def __init__(self, text_edit: QTextEdit, error_label: QLabel):
        self.text_edit = text_edit
        self.error_label = error_label

    def _set_label(self, message: str):
        self.error_label.setText(message)
        self.error_label.setVisible(True)

    def validate(self, input_str: str) -> ValidationState:
        # initial set to 3 for parsing and validating first 2 characters
        pubkey_max_length = 3
        self.error_label.setVisible(False)

        if len(input_str) > 2:
            prefix = input_str[:2]
            if prefix in self.COMPRESSED_PREFIXES:
                pubkey_max_length = self.COMPRESSED_PUBKEY_LENGTH
            elif prefix == self.UNCOMPRESSED_PREFIXES:
                pubkey_max_length = self.UNCOMPRESSED_PUBKEY_LENGTH
            else:
                self._set_label(_('Wrong prefix. It is neither compressed nor uncompressed'))
                return ValidationState.INVALID

        if len(input_str) < pubkey_max_length:
            return ValidationState.INTERMEDIATE
        if len(input_str) > pubkey_max_length:
            self._set_label(_('PubKey cropped because too long string passed'))
            return ValidationState.CROPPED
        return self.is_pubkey(input_str)

    def _fixup_too_long_pubkey(self, input_str: str, pubkey_max_length: int):
        pubkey = input_str[:pubkey_max_length]
        return self.validate(pubkey)

    def is_pubkey(self, pubkey_str: str) -> ValidationState:
        try:
            pubkey_bytes = bytes.fromhex(pubkey_str)
        except ValueError:
            self._set_label(_('Wrong pubkey format'))
            return ValidationState.INVALID

        if not ECPubkey.is_pubkey_bytes(pubkey_bytes):
            self._set_label(_('Wrong pubkey format'))
            return ValidationState.INVALID

        return ValidationState.VALID


class ErrorLabel(QLabel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setStyleSheet("font-weight: bold; color: red")


class InsertPubKeyDialog(QVBoxLayout):
    def __init__(self, parent, message_label):
        super().__init__()
        self.parent = parent
        self._if_apply_validation_logic = True
        label = message_label
        edit = QTextEdit()
        error_label = ErrorLabel()

        self.validator = PubKeyValidator(edit, error_label)
        edit.textChanged.connect(self._on_change)
        self.addWidget(label)
        self.addWidget(edit)
        self.addWidget(error_label)
        self.edit = edit

    def _on_change(self):
        if self._if_apply_validation_logic:
            self._apply_validation_logic()
        else:
            self._if_apply_validation_logic = True

    def _delete_last_character_from_input(self):
        self._if_apply_validation_logic = False
        self.edit.textCursor().deletePreviousChar()

    def _apply_validation_logic(self):
        self.parent.next_button.setEnabled(False)
        pubkey_candidate = self._get_str()
        state = self.validator.validate(pubkey_candidate)
        if state == ValidationState.INVALID:
            self._delete_last_character_from_input()
        elif state == ValidationState.VALID:
            self.parent.next_button.setEnabled(True)
        elif state == ValidationState.CROPPED:
            self.parent.next_button.setEnabled(True)
            self._delete_last_character_from_input()

    def _get_str(self) -> str:
        return self.edit.toPlainText()

    def get_compressed_pubkey(self):
        bytes_ = bytes.fromhex(self._get_str())
        pubkey = ECPubkey(bytes_)
        return pubkey.get_public_key_hex(compressed=True)


class Qr2FaDialog(QVBoxLayout):
    def __init__(self, parent, title_label: str, pin_label: str, qr_data: dict):
        super().__init__()
        self.parent = parent
        self.pubkey = ECPrivkey(short_mnemonic.entropy_to_privkey(qr_data['entropy'])).get_public_key_hex()
        qr = QRCodeWidget(self.prepare_qr_data_for_display(qr_data))
        self.edit = QLineEdit()
        self.edit.setMaxLength(4)
        self.edit.setFixedWidth(50)
        self.edit.setFont(QFont("Monospace"))
        self.edit.textChanged.connect(self._on_change)
        self.addWidget(title_label, alignment=Qt.AlignCenter)
        self.addWidget(qr, alignment=Qt.AlignCenter)
        self.addWidget(pin_label, alignment=Qt.AlignCenter)
        self.addWidget(self.edit, alignment=Qt.AlignCenter)

    def _on_change(self):
        self.parent.next_button.setEnabled(False)
        self.pin_candidate = self.edit.text()
        if self.pubkey[-4:] == self.pin_candidate:
            self.parent.next_button.setEnabled(True)

    def get_pubkey(self) -> str:
        return self.pubkey

    @staticmethod
    def prepare_qr_data_for_display(qr_data: dict) -> dict:
        new_qr_data = copy.deepcopy(qr_data)
        new_qr_data['entropy'] = new_qr_data['entropy'].hex()
        return new_qr_data
