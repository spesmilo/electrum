# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'personalization-seedbackup-01.ui'
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
        self.TitleLabel.setGeometry(QtCore.QRect(30, 20, 351, 31))
        font = QtGui.QFont()
        font.setPointSize(20)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.TitleLabel.setFont(font)
        self.TitleLabel.setObjectName(_fromUtf8("TitleLabel"))
        self.NextButton = QtGui.QPushButton(Dialog)
        self.NextButton.setGeometry(QtCore.QRect(320, 270, 75, 25))
        self.NextButton.setObjectName(_fromUtf8("NextButton"))
        self.IntroLabel = QtGui.QLabel(Dialog)
        self.IntroLabel.setGeometry(QtCore.QRect(10, 100, 351, 31))
        self.IntroLabel.setWordWrap(True)
        self.IntroLabel.setObjectName(_fromUtf8("IntroLabel"))
        self.IntroLabel_2 = QtGui.QLabel(Dialog)
        self.IntroLabel_2.setGeometry(QtCore.QRect(10, 140, 351, 31))
        self.IntroLabel_2.setWordWrap(True)
        self.IntroLabel_2.setObjectName(_fromUtf8("IntroLabel_2"))
        self.IntroLabel_3 = QtGui.QLabel(Dialog)
        self.IntroLabel_3.setGeometry(QtCore.QRect(10, 180, 351, 41))
        self.IntroLabel_3.setWordWrap(True)
        self.IntroLabel_3.setObjectName(_fromUtf8("IntroLabel_3"))
        self.TitleLabel_2 = QtGui.QLabel(Dialog)
        self.TitleLabel_2.setGeometry(QtCore.QRect(90, 60, 251, 31))
        font = QtGui.QFont()
        font.setPointSize(20)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.TitleLabel_2.setFont(font)
        self.TitleLabel_2.setObjectName(_fromUtf8("TitleLabel_2"))
        self.IntroLabel_4 = QtGui.QLabel(Dialog)
        self.IntroLabel_4.setGeometry(QtCore.QRect(10, 220, 351, 41))
        self.IntroLabel_4.setWordWrap(True)
        self.IntroLabel_4.setObjectName(_fromUtf8("IntroLabel_4"))

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "BTChip setup", None, QtGui.QApplication.UnicodeUTF8))
        self.TitleLabel.setText(QtGui.QApplication.translate("Dialog", "BTChip setup  - seed backup", None, QtGui.QApplication.UnicodeUTF8))
        self.NextButton.setText(QtGui.QApplication.translate("Dialog", "Next", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel.setText(QtGui.QApplication.translate("Dialog", "A new seed has been generated for your wallet.", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_2.setText(QtGui.QApplication.translate("Dialog", "You must backup this seed and keep it out of reach of hackers (typically by keeping it on paper).", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_3.setText(QtGui.QApplication.translate("Dialog", "You can use this seed to restore your dongle if you lose it or access your funds with any other compatible wallet.", None, QtGui.QApplication.UnicodeUTF8))
        self.TitleLabel_2.setText(QtGui.QApplication.translate("Dialog", "READ CAREFULLY", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_4.setText(QtGui.QApplication.translate("Dialog", "Press Next to start the backuping process.", None, QtGui.QApplication.UnicodeUTF8))

