# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'personalization-04-finalize.ui'
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
        Dialog.resize(400, 267)
        self.TitleLabel = QtGui.QLabel(Dialog)
        self.TitleLabel.setGeometry(QtCore.QRect(20, 20, 361, 31))
        font = QtGui.QFont()
        font.setPointSize(20)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.TitleLabel.setFont(font)
        self.TitleLabel.setObjectName(_fromUtf8("TitleLabel"))
        self.FinishButton = QtGui.QPushButton(Dialog)
        self.FinishButton.setGeometry(QtCore.QRect(320, 230, 75, 25))
        self.FinishButton.setObjectName(_fromUtf8("FinishButton"))
        self.IntroLabel_4 = QtGui.QLabel(Dialog)
        self.IntroLabel_4.setGeometry(QtCore.QRect(10, 70, 351, 61))
        self.IntroLabel_4.setWordWrap(True)
        self.IntroLabel_4.setObjectName(_fromUtf8("IntroLabel_4"))
        self.IntroLabel_5 = QtGui.QLabel(Dialog)
        self.IntroLabel_5.setGeometry(QtCore.QRect(50, 140, 121, 21))
        self.IntroLabel_5.setWordWrap(True)
        self.IntroLabel_5.setObjectName(_fromUtf8("IntroLabel_5"))
        self.pin1 = QtGui.QLineEdit(Dialog)
        self.pin1.setGeometry(QtCore.QRect(200, 140, 181, 21))
        self.pin1.setEchoMode(QtGui.QLineEdit.Password)
        self.pin1.setObjectName(_fromUtf8("pin1"))
        self.remainingAttemptsLabel = QtGui.QLabel(Dialog)
        self.remainingAttemptsLabel.setGeometry(QtCore.QRect(120, 170, 171, 31))
        font = QtGui.QFont()
        font.setItalic(True)
        self.remainingAttemptsLabel.setFont(font)
        self.remainingAttemptsLabel.setWordWrap(True)
        self.remainingAttemptsLabel.setObjectName(_fromUtf8("remainingAttemptsLabel"))

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "BTChip setup - security", None, QtGui.QApplication.UnicodeUTF8))
        self.TitleLabel.setText(QtGui.QApplication.translate("Dialog", "BTChip setup - completed", None, QtGui.QApplication.UnicodeUTF8))
        self.FinishButton.setText(QtGui.QApplication.translate("Dialog", "Finish", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_4.setText(QtGui.QApplication.translate("Dialog", "BTChip setup is completed. Please enter your PIN to validate it then press Finish", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_5.setText(QtGui.QApplication.translate("Dialog", "BTChip PIN :", None, QtGui.QApplication.UnicodeUTF8))
        self.remainingAttemptsLabel.setText(QtGui.QApplication.translate("Dialog", "Remaining attempts", None, QtGui.QApplication.UnicodeUTF8))

