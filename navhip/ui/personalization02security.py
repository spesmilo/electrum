# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'personalization-02-security.ui'
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
        Dialog.resize(400, 503)
        self.TitleLabel = QtGui.QLabel(Dialog)
        self.TitleLabel.setGeometry(QtCore.QRect(20, 20, 361, 31))
        font = QtGui.QFont()
        font.setPointSize(20)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.TitleLabel.setFont(font)
        self.TitleLabel.setObjectName(_fromUtf8("TitleLabel"))
        self.IntroLabel = QtGui.QLabel(Dialog)
        self.IntroLabel.setGeometry(QtCore.QRect(10, 60, 351, 61))
        self.IntroLabel.setWordWrap(True)
        self.IntroLabel.setObjectName(_fromUtf8("IntroLabel"))
        self.HardenedButton = QtGui.QRadioButton(Dialog)
        self.HardenedButton.setGeometry(QtCore.QRect(20, 110, 81, 21))
        self.HardenedButton.setChecked(True)
        self.HardenedButton.setObjectName(_fromUtf8("HardenedButton"))
        self.buttonGroup = QtGui.QButtonGroup(Dialog)
        self.buttonGroup.setObjectName(_fromUtf8("buttonGroup"))
        self.buttonGroup.addButton(self.HardenedButton)
        self.HardenedButton_2 = QtGui.QRadioButton(Dialog)
        self.HardenedButton_2.setGeometry(QtCore.QRect(20, 210, 81, 21))
        self.HardenedButton_2.setObjectName(_fromUtf8("HardenedButton_2"))
        self.buttonGroup.addButton(self.HardenedButton_2)
        self.IntroLabel_2 = QtGui.QLabel(Dialog)
        self.IntroLabel_2.setGeometry(QtCore.QRect(50, 140, 351, 61))
        self.IntroLabel_2.setWordWrap(True)
        self.IntroLabel_2.setObjectName(_fromUtf8("IntroLabel_2"))
        self.IntroLabel_3 = QtGui.QLabel(Dialog)
        self.IntroLabel_3.setGeometry(QtCore.QRect(50, 230, 351, 61))
        self.IntroLabel_3.setWordWrap(True)
        self.IntroLabel_3.setObjectName(_fromUtf8("IntroLabel_3"))
        self.CancelButton = QtGui.QPushButton(Dialog)
        self.CancelButton.setGeometry(QtCore.QRect(10, 470, 75, 25))
        self.CancelButton.setObjectName(_fromUtf8("CancelButton"))
        self.NextButton = QtGui.QPushButton(Dialog)
        self.NextButton.setGeometry(QtCore.QRect(310, 470, 75, 25))
        self.NextButton.setObjectName(_fromUtf8("NextButton"))
        self.IntroLabel_4 = QtGui.QLabel(Dialog)
        self.IntroLabel_4.setGeometry(QtCore.QRect(10, 300, 351, 61))
        self.IntroLabel_4.setWordWrap(True)
        self.IntroLabel_4.setObjectName(_fromUtf8("IntroLabel_4"))
        self.IntroLabel_5 = QtGui.QLabel(Dialog)
        self.IntroLabel_5.setGeometry(QtCore.QRect(20, 380, 161, 31))
        self.IntroLabel_5.setWordWrap(True)
        self.IntroLabel_5.setObjectName(_fromUtf8("IntroLabel_5"))
        self.pin1 = QtGui.QLineEdit(Dialog)
        self.pin1.setGeometry(QtCore.QRect(210, 380, 161, 21))
        self.pin1.setEchoMode(QtGui.QLineEdit.Password)
        self.pin1.setObjectName(_fromUtf8("pin1"))
        self.pin2 = QtGui.QLineEdit(Dialog)
        self.pin2.setGeometry(QtCore.QRect(210, 420, 161, 21))
        self.pin2.setEchoMode(QtGui.QLineEdit.Password)
        self.pin2.setObjectName(_fromUtf8("pin2"))
        self.IntroLabel_6 = QtGui.QLabel(Dialog)
        self.IntroLabel_6.setGeometry(QtCore.QRect(20, 420, 171, 31))
        self.IntroLabel_6.setWordWrap(True)
        self.IntroLabel_6.setObjectName(_fromUtf8("IntroLabel_6"))

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "BTChip setup - security", None, QtGui.QApplication.UnicodeUTF8))
        self.TitleLabel.setText(QtGui.QApplication.translate("Dialog", "BTChip setup - security (2/3)", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel.setText(QtGui.QApplication.translate("Dialog", "Please choose a security profile", None, QtGui.QApplication.UnicodeUTF8))
        self.HardenedButton.setText(QtGui.QApplication.translate("Dialog", "Hardened", None, QtGui.QApplication.UnicodeUTF8))
        self.HardenedButton_2.setText(QtGui.QApplication.translate("Dialog", "PIN only", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_2.setText(QtGui.QApplication.translate("Dialog", "You need to remove the dongle and insert it again to get a second factor validation of all operations. Recommended for expert users and to be fully protected against malwares.", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_3.setText(QtGui.QApplication.translate("Dialog", "You only need to enter a PIN once when inserting the dongle. Transactions are not protected against malwares", None, QtGui.QApplication.UnicodeUTF8))
        self.CancelButton.setText(QtGui.QApplication.translate("Dialog", "Cancel", None, QtGui.QApplication.UnicodeUTF8))
        self.NextButton.setText(QtGui.QApplication.translate("Dialog", "Next", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_4.setText(QtGui.QApplication.translate("Dialog", "Please choose a PIN associated to the BTChip dongle. The PIN protects the dongle in case it is stolen, and can be up to 32 characters. The dongle is wiped  if a wrong PIN is entered 3 times in a row.", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_5.setText(QtGui.QApplication.translate("Dialog", "Enter the new PIN : ", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_6.setText(QtGui.QApplication.translate("Dialog", "Repeat the new PIN :", None, QtGui.QApplication.UnicodeUTF8))

