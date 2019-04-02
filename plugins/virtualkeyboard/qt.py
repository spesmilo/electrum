from PyQt5.QtGui import *
from PyQt5.QtWidgets import (QVBoxLayout, QGridLayout, QPushButton)
from electroncash.plugins import BasePlugin, hook
from electroncash.i18n import _
from electroncash_gui.qt.util import MONOSPACE_FONT
import random


class Plugin(BasePlugin):
    vkb = None
    vkb_index = 0

    @hook
    def password_dialog(self, pw, grid, pos):
        vkb_button = QPushButton(_("+"))
        vkb_button.setFixedWidth(20)
        vkb_button.clicked.connect(lambda: self.toggle_vkb(grid, pw))
        grid.addWidget(vkb_button, pos, 2)
        self.kb_pos = 2
        self.vkb = None

    def toggle_vkb(self, grid, pw):
        if self.vkb:
            grid.removeItem(self.vkb)
        self.vkb = self.virtual_keyboard(self.vkb_index, pw)
        grid.addLayout(self.vkb, self.kb_pos, 0, 1, 3)
        self.vkb_index += 1

    def virtual_keyboard(self, i, pw):
        i = i % 3
        if i == 0:
            chars = 'abcdefghijklmnopqrstuvwxyz '
        elif i == 1:
            chars = 'ABCDEFGHIJKLMNOPQRTSUVWXYZ '
        elif i == 2:
            chars = '1234567890!?.,;:/%&()[]{}+-'

        s = list(chars)
        random.shuffle(s)

        def add_target(t):
            return lambda: pw.setText(str(pw.text()) + t)

        vbox = QVBoxLayout()
        grid = QGridLayout()
        grid.setSpacing(2)
        font = QFont(MONOSPACE_FONT)
        for i,c in enumerate(s):
            l_button = QPushButton(c)
            l_button.setFont(font)
            l_button.clicked.connect(add_target(c))
            grid.addWidget(l_button, i // 6, i % 6)

        vbox.addLayout(grid)

        return vbox
