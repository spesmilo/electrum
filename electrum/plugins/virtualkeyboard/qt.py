import random

from PyQt5.QtWidgets import (QVBoxLayout, QGridLayout, QPushButton)
from PyQt5.QtGui import QFontMetrics

from electrum.plugin import BasePlugin, hook
from electrum.i18n import _


class Plugin(BasePlugin):
    vkb = None
    vkb_index = 0

    @hook
    def password_dialog(self, wallet, pw, grid, pos):
        vkb_button = QPushButton("+")
        font_height = QFontMetrics(vkb_button.font()).height()
        vkb_button.setFixedWidth(round(1.7 * font_height))
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

        n = len(chars)
        s = []
        for i in range(n):
            while True:
                k = random.randint(0, n - 1)
                if k not in s:
                    s.append(k)
                    break

        def add_target(t):
            return lambda: pw.setText(str(pw.text()) + t)

        font_height = QFontMetrics(QPushButton().font()).height()
        btn_size = max(25, round(1.7 * font_height))

        vbox = QVBoxLayout()
        grid = QGridLayout()
        grid.setSpacing(2)
        for i in range(n):
            l_button = QPushButton(chars[s[i]])
            l_button.setFixedWidth(btn_size)
            l_button.setFixedHeight(btn_size)
            l_button.clicked.connect(add_target(chars[s[i]]))
            grid.addWidget(l_button, i // 6, i % 6)

        vbox.addLayout(grid)

        return vbox
