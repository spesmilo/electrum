#!/usr/bin/python

from PyQt5 import QtWidgets, QtCore, QtGui
from electrum.i18n import _
from electrum.gui.qt.util import WindowModalDialog
from .deniability import Deniability

class Plugin(Deniability):

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        btn = QtWidgets.QPushButton(_("Settings"))
        btn.clicked.connect(lambda: self.settings_dialog(window))
        return btn

    def settings_dialog(self, window):

        saved_budget = float(self.config.get('deniability_budget', 0))
        rounded_budget = round(saved_budget, 2)

        d = WindowModalDialog(window, _("Deniability Budget"))
        self.d = d
        layout = QtWidgets.QVBoxLayout(d)
        self.slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.slider.setMinimum(0)
        self.slider.setMaximum(10)
        self.slider.setValue(int(rounded_budget * 100))
        self.slider.valueChanged.connect(self.change_budget)
        self.current_label = QtWidgets.QLabel(str(saved_budget) + " BTC")
        self.slider.valueChanged.connect(self.update_current_label)
        layout.addWidget(self.slider)
        layout.addWidget(self.current_label)
        ok_button  = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok, d)
        layout.addWidget(ok_button)
        ok_button.accepted.connect(self.ok_clicked)
        d.exec_()

    def ok_clicked(self):

        self.budget = self.slider.value()/100
        self.config.set_key('deniability_budget',self.budget,True)
        self.d.accept()

    def update_current_label(self):
        self.current_label.setText(f"{self.budget:.2f} BTC")

    def change_budget(self, value):
        self.budget = value / 100