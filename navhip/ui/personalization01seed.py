# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'personalization-01-seed.ui'
#
# Created: Thu Aug 28 22:26:22 2014
#      by: PyQt4 UI code generator 4.9.1
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(400, 300)
        self.TitleLabel = QtGui.QLabel(Dialog)
        self.TitleLabel.setGeometry(QtCore.QRect(50, 20, 311, 31))
        font = QtGui.QFont()
        font.setPointSize(20)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.TitleLabel.setFont(font)
        self.TitleLabel.setObjectName(_fromUtf8("TitleLabel"))
        self.IntroLabel = QtGui.QLabel(Dialog)
        self.IntroLabel.setGeometry(QtCore.QRect(20, 60, 351, 61))
        self.IntroLabel.setWordWrap(True)
        self.IntroLabel.setObjectName(_fromUtf8("IntroLabel"))
        self.NewWalletButton = QtGui.QRadioButton(Dialog)
        self.NewWalletButton.setGeometry(QtCore.QRect(20, 130, 94, 21))
        self.NewWalletButton.setChecked(True)
        self.NewWalletButton.setObjectName(_fromUtf8("NewWalletButton"))
        self.buttonGroup = QtGui.QButtonGroup(Dialog)
        self.buttonGroup.setObjectName(_fromUtf8("buttonGroup"))
        self.buttonGroup.addButton(self.NewWalletButton)
        self.RestoreWalletButton = QtGui.QRadioButton(Dialog)
        self.RestoreWalletButton.setGeometry(QtCore.QRect(20, 180, 171, 21))
        self.RestoreWalletButton.setObjectName(_fromUtf8("RestoreWalletButton"))
        self.buttonGroup.addButton(self.RestoreWalletButton)
        self.seed = QtGui.QLineEdit(Dialog)
        self.seed.setEnabled(False)
        self.seed.setGeometry(QtCore.QRect(50, 210, 331, 21))
        self.seed.setEchoMode(QtGui.QLineEdit.Normal)
        self.seed.setObjectName(_fromUtf8("seed"))
        self.CancelButton = QtGui.QPushButton(Dialog)
        self.CancelButton.setGeometry(QtCore.QRect(10, 270, 75, 25))
        self.CancelButton.setObjectName(_fromUtf8("CancelButton"))
        self.NextButton = QtGui.QPushButton(Dialog)
        self.NextButton.setGeometry(QtCore.QRect(320, 270, 75, 25))
        self.NextButton.setObjectName(_fromUtf8("NextButton"))
        self.mnemonicNotAvailableLabel = QtGui.QLabel(Dialog)
        self.mnemonicNotAvailableLabel.setGeometry(QtCore.QRect(130, 240, 171, 31))
        font = QtGui.QFont()
        font.setItalic(True)
        self.mnemonicNotAvailableLabel.setFont(font)
        self.mnemonicNotAvailableLabel.setWordWrap(True)
        self.mnemonicNotAvailableLabel.setObjectName(_fromUtf8("mnemonicNotAvailableLabel"))

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "BTChip setup - seed", None, QtGui.QApplication.UnicodeUTF8))
        self.TitleLabel.setText(QtGui.QApplication.translate("Dialog", "BTChip setup - seed (1/3)", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel.setText(QtGui.QApplication.translate("Dialog", "Please select an option : either create a new wallet or restore an existing one", None, QtGui.QApplication.UnicodeUTF8))
        self.NewWalletButton.setText(QtGui.QApplication.translate("Dialog", "New Wallet", None, QtGui.QApplication.UnicodeUTF8))
        self.RestoreWalletButton.setText(QtGui.QApplication.translate("Dialog", "Restore wallet backup", None, QtGui.QApplication.UnicodeUTF8))
        self.seed.setPlaceholderText(QtGui.QApplication.translate("Dialog", "Enter an hexadecimal seed or a BIP 39 mnemonic code", None, QtGui.QApplication.UnicodeUTF8))
        self.CancelButton.setText(QtGui.QApplication.translate("Dialog", "Cancel", None, QtGui.QApplication.UnicodeUTF8))
        self.NextButton.setText(QtGui.QApplication.translate("Dialog", "Next", None, QtGui.QApplication.UnicodeUTF8))
        self.mnemonicNotAvailableLabel.setText(QtGui.QApplication.translate("Dialog", "Mnemonic API is not available", None, QtGui.QApplication.UnicodeUTF8))

